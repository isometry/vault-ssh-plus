package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hashicorp/vault/api"
	"github.com/isometry/vault-ssh-client/openssh"
	"github.com/jessevdk/go-flags"
)

type options struct {
	Path           string `long:"path" default:"ssh" env:"VAULT_SSH_PATH" description:"Vault SSH Path"`
	Role           string `long:"role" default:"default" env:"VAULT_SSH_ROLE" description:"Vault SSH Role"`
	TTL            uint   `long:"ttl" default:"300" env:"VAULT_SSH_TTL" description:"Vault SSH Certificate TTL"`
	PortForwarding bool   `long:"port-forwarding" env:"VAULT_SSH_PORT_FORWARDING" description:"Force permit-port-forwarding extension"`
	PTY            bool   `long:"pty" env:"VAULT_SSH_PTY" description:"Force permit-pty extension"`
	// TODO: make private key optional to support PKCS#11 keys
	PrivateKey string `long:"key" default:"~/.ssh/id_rsa" env:"VAULT_SSH_PRIVATE_KEY" description:"OpenSSH Private RSA Key"`
	PublicKey  string `long:"pub" default:"~/.ssh/id_rsa.pub" env:"VAULT_SSH_PUBLIC_KEY" description:"OpenSSH Public RSA Key to sign"`
	Exec       bool   `long:"exec" env:"VAULT_SSH_EXEC" description:"Call ssh via execve(2)"`
}

var opts options

// getToken uses the standard vault client binary to retrieve the "current" default token, avoiding reimplementation of token_helper, etc.
func getTokenFromHelper() string {
	token, err := exec.Command(vaultBinary, "read", "-field=id", "auth/token/lookup-self").Output()
	if err != nil {
		log.Fatal("failed to read token: ", err)
	}
	return string(token)
}

func main() {
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash|flags.IgnoreUnknown)
	sshArgs, err := parser.ParseArgs(os.Args[1:])
	if err != nil {
		log.Fatal("failed to parse arguments: ", err)
	}

	sshOpts := openssh.ParseArgs(sshArgs)

	currentUser, _ := user.Current()

	if sshOpts.LoginName == "" {
		sshOpts.LoginName = currentUser.Username
	}

	homeDir := currentUser.HomeDir

	if strings.HasPrefix(opts.PrivateKey, "~/") {
		opts.PrivateKey = filepath.Join(homeDir, opts.PrivateKey[2:])
	}

	if strings.HasPrefix(opts.PublicKey, "~/") {
		opts.PublicKey = filepath.Join(homeDir, opts.PublicKey[2:])
	}

	controlConnection := testControlConnection(sshArgs)

	var cmdArgs []string
	if controlConnection {
		cmdArgs = sshArgs
	} else {
		signedPublicKey := getSignedKeyFile(opts, sshOpts)
		defer os.Remove(signedPublicKey)
		cmdArgs = append([]string{
			"-o", "IdentitiesOnly=yes",
			"-i", signedPublicKey,
			"-i", opts.PrivateKey,
		}, sshArgs...)
	}

	log.Printf("%v %v\n", cmdArgs, controlConnection)

	if opts.Exec {
		sshPath, err := exec.LookPath(sshBinary)
		if err != nil {
			log.Fatal("ssh binary not found in PATH: ", err)
		}

		err = syscall.Exec(sshPath, append([]string{sshBinary}, cmdArgs...), os.Environ())
		if err != nil {
			log.Fatal("failed to exec ssh: ", err)
		}
	} else {
		cmd := exec.Command(sshBinary, cmdArgs...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

		err = cmd.Run()
		if err != nil {
			log.Fatal("error running ssh: ", err)
		}
	}
}

func testControlConnection(args []string) bool {
	cmdArgs := append([]string{"-O", "check"}, args...)
	cmd := exec.Command(sshBinary, cmdArgs...)
	_, err := cmd.Output()
	return (err == nil)
}

func getSignedKeyFile(opts options, sshOpts openssh.Options) string {
	publicKeyBytes, err := ioutil.ReadFile(opts.PublicKey)
	if err != nil {
		log.Fatal("failed to read public key: ", err)
	}

	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		log.Fatal("failed to read environment: ", err)
	}

	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatal("failed to create vault client: ", err)
	}

	vaultToken := vaultClient.Token()
	if vaultToken == "" {
		vaultToken = getTokenFromHelper()
	}

	vaultClient.SetToken(vaultToken)

	vaultSSH := vaultClient.SSHWithMountPoint(opts.Path)

	request := make(map[string]interface{})

	request["public_key"] = string(publicKeyBytes)
	request["valid_principals"] = sshOpts.LoginName
	request["ttl"] = opts.TTL

	extensions := map[string]string{}

	if opts.PTY || len(sshOpts.ForcePTY) > 0 {
		extensions["permit-pty"] = ""
	}

	if opts.PortForwarding ||
		sshOpts.JumpHost != "" ||
		sshOpts.DynamicPortForwarding != "" ||
		sshOpts.LocalForwarding != nil ||
		sshOpts.RemoteForwarding != nil {
		extensions["permit-port-forwarding"] = ""
	}

	// accept default_extensions unless explicitly overridden by opts
	if len(extensions) > 0 {
		request["extensions"] = extensions
	}
	log.Printf("%v\n", extensions)
	// request["extensions"] = extensions

	signedPublicKey, err := vaultSSH.SignKey(opts.Role, request)
	if err != nil {
		log.Fatal("failed to sign key: ", err)
	}

	signedPublicKeyFileNameTemplate := fmt.Sprintf("%s_%s-cert.pub.*", filepath.Base(opts.PrivateKey), sshOpts.LoginName)
	signedPublicKeyFile, err := ioutil.TempFile(filepath.Dir(opts.PrivateKey), signedPublicKeyFileNameTemplate)
	if err != nil {
		log.Fatal("failed to create temporary public key file: ", err)
	}
	setupExitHandler(signedPublicKeyFile.Name())

	signedPublicKeyData := signedPublicKey.Data["signed_key"].(string)

	if signedPublicKeyData == "" {
		log.Fatalf("bad signedPublicKeydata: %v", signedPublicKeyData)
	}

	if _, err = signedPublicKeyFile.Write([]byte(signedPublicKeyData)); err != nil {
		log.Fatal("failed to write to temporary signed key file: ", err)
	}
	if err := signedPublicKeyFile.Close(); err != nil {
		log.Fatal("failed to close temporary signed key file: ", err)
	}

	return signedPublicKeyFile.Name()
}

func setupExitHandler(signedPublicKeyFile string) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		_ = os.Remove(signedPublicKeyFile)
		os.Exit(0)
	}()
}
