package signer

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
	"github.com/jessevdk/go-flags"
)

type Client struct {
	MountPoint *api.SSH
	Options    Options
	SignedKey  string
}

type Options struct {
	Path           string `long:"path" default:"ssh" env:"VAULT_SSH_PATH" description:"Vault SSH Path"`
	Role           string `long:"role" default:"default" env:"VAULT_SSH_ROLE" description:"Vault SSH Role"`
	TTL            uint   `long:"ttl" default:"300" env:"VAULT_SSH_TTL" description:"Vault SSH Certificate TTL"`
	PortForwarding bool   `long:"port-forwarding" env:"VAULT_SSH_PORT_FORWARDING" description:"Force permit-port-forwarding extension"`
	PTY            bool   `long:"pty" env:"VAULT_SSH_PTY" description:"Force permit-pty extension"`
	PublicKey      string `short:"P" long:"public-key" default:"~/.ssh/id_rsa.pub" env:"VAULT_SSH_PUBLIC_KEY" description:"OpenSSH Public RSA Key to sign"`
}

func ParseArgs(args []string) (Client, []string) {
	var options Options

	parser := flags.NewParser(&options, flags.HelpFlag|flags.PassDoubleDash|flags.IgnoreUnknown)
	unparsedArgs, err := parser.ParseArgs(args)
	if err != nil {
		log.Fatal("error parsing vault args: ", err)
	}

	currentUser, _ := user.Current()
	if err != nil {
		log.Fatal("unable to determine current user: ", err)
	}
	homeDir := currentUser.HomeDir

	if strings.HasPrefix(options.PublicKey, "~/") {
		options.PublicKey = filepath.Join(homeDir, options.PublicKey[2:])
	}

	if _, err := os.Stat(options.PublicKey); os.IsNotExist(err) {
		log.Fatal("public key does not exist: ", err)
	}

	// TODO: further validate public key

	// VaultClient instance is not fully initialised!
	vault := Client{
		Options: options,
	}

	return vault, unparsedArgs
}

// GetTokenFromHelper uses the standard vault client binary to retrieve the "current" default token, avoiding reimplementation of token_helper, etc.
func GetTokenFromHelper() string {
	token, err := exec.Command(clientBinary, "read", "-field=id", "auth/token/lookup-self").Output()
	if err != nil {
		log.Fatal("failed to read token: ", err)
	}
	return string(token)
}

// SetMountPoint sets the MountPoint attribute to the appropriate Vault API SSH MountPoint
func (c *Client) SetMountPoint() {
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
		vaultToken = GetTokenFromHelper()
	}

	vaultClient.SetToken(vaultToken)

	c.MountPoint = vaultClient.SSHWithMountPoint(c.Options.Path)
}

// SignKey signs the configured public key, sets the SignedKey property to the filename of the signed key and returns the filename
func (c *Client) SignKey(principal string) string {
	publicKeyBytes, err := ioutil.ReadFile(c.Options.PublicKey)
	if err != nil {
		log.Fatal("failed to read public key: ", err)
	}

	request := make(map[string]interface{})

	request["public_key"] = string(publicKeyBytes)
	request["valid_principals"] = principal
	request["ttl"] = c.Options.TTL

	extensions := map[string]string{}

	if c.Options.PTY {
		extensions["permit-pty"] = ""
	}

	if c.Options.PortForwarding {
		extensions["permit-port-forwarding"] = ""
	}

	// accept role default_extensions unless explicitly overridden by options
	if len(extensions) > 0 {
		request["extensions"] = extensions
		log.Printf("[DEBUG] %v\n", extensions)
	}

	c.SetMountPoint()

	signedKeySecret, err := c.MountPoint.SignKey(c.Options.Role, request)
	if err != nil {
		log.Fatal("failed to sign key: ", err)
	}

	signedKeyFileTemplate := fmt.Sprintf("signed_%s@path=%s:role=%s:principal=%s.*", filepath.Base(c.Options.PublicKey), c.Options.Path, c.Options.Role, principal)
	signedKeyFile, err := ioutil.TempFile(filepath.Dir(c.Options.PublicKey), signedKeyFileTemplate)
	if err != nil {
		log.Fatal("failed to create temporary public key file: ", err)
	}

	// ensure the signedKeyFile is deleted if we're killed
	c.setupExitHandler()

	if _, err = signedKeyFile.Write([]byte(signedKeySecret.Data["signed_key"].(string))); err != nil {
		log.Fatal("failed to write to temporary signed key file: ", err)
	}

	if err := signedKeyFile.Close(); err != nil {
		log.Fatal("failed to close temporary signed key file: ", err)
	}

	c.SignedKey = signedKeyFile.Name()

	return c.SignedKey
}

func (c *Client) setupExitHandler() {
	s := make(chan os.Signal)
	signal.Notify(s, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-s
		_ = os.Remove(c.SignedKey)
		os.Exit(0)
	}()
}
