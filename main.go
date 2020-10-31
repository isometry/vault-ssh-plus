package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/isometry/vault-ssh-plus/openssh"
	"github.com/isometry/vault-ssh-plus/signer"
	"github.com/jessevdk/go-flags"
)

const (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	var options struct {
		Signer  signer.Options  `group:"Vault SSH key signing Options"`
		OpenSSH openssh.Options `group:"OpenSSH ssh(1) Options" hidden:"yes"`
		Version func()          `long:"version" description:"Show version"`
	}

	options.Version = func() {
		fmt.Printf("vault-ssh-plus v%s (%s), %s\n", version, commit, date)
		os.Exit(0)
	}

	parser := flags.NewParser(&options, flags.Default)
	parser.Usage = "[options] destination [command]"
	if _, err := parser.ParseArgs(os.Args[1:]); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}
}

func main() {
	var (
		vaultClient signer.Client
		sshClient   openssh.Client
		err         error
	)

	unparsedArgs, err := signer.ParseArgs(&vaultClient, os.Args[1:])
	if err != nil {
		log.Fatal("[ERROR] parsing vault options: ", err)
	}

	_, err = openssh.ParseArgs(&sshClient, unparsedArgs)
	if err != nil {
		log.Fatal("[ERROR] parsing ssh options: ", err)
	}

	if sshClient.Options.LoginName == "" {
		sshClient.Options.LoginName = getDefaultUser(&vaultClient, &sshClient)
	}

	controlConnection := sshClient.ControlConnection()

	if !controlConnection && sshClient.Options.ControlCommand != "exit" {
		updateRequestExtensions(&vaultClient.Options.Extensions, &sshClient.Options)

		signedKey, err := vaultClient.GetSignedKey(sshClient.Options.LoginName)
		if err != nil {
			log.Fatal("[ERROR] failed to get signed key: ", err)
		}

		if err := sshClient.SetSignedKey(signedKey); err != nil {
			log.Fatal("[ERROR] invalid certificate: ", err)
		}

		signedKeyFile, err := sshClient.WriteSignedKeyFile(
			filepath.Dir(vaultClient.Options.PublicKey),
			fmt.Sprintf("signed_%s@*", filepath.Base(vaultClient.Options.PublicKey)),
		)
		if err != nil {
			log.Fatal("[ERROR] failed to write signed key to file: ", err)
		}

		// ensure the signedKeyFile is deleted if we're killed
		setupExitHandler(signedKeyFile)
		defer os.Remove(signedKeyFile)

		sshClient.PrependArgs([]string{"-o", fmt.Sprintf("CertificateFile=%s", signedKeyFile)})
		// sshClient.PrependArgs([]string{"-i", signedKeyFile})
	}

	log.Printf("[DEBUG] %v %v\n", sshClient.Args, controlConnection)

	if err := sshClient.Connect(); err != nil {
		log.Fatal("failed to connect: ", err)
	}
}

func setupExitHandler(fn string) {
	s := make(chan os.Signal)
	signal.Notify(s, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-s
		_ = os.Remove(fn)
		os.Exit(0)
	}()
}

func getDefaultUser(vaultClient *signer.Client, sshClient *openssh.Client) string {
	var loginName string

	// if the role only allows a single, fixed user, use it
	allowedUser := vaultClient.GetAllowedUser()
	if allowedUser != "" {
		loginName = allowedUser
		sshClient.PrependArgs([]string{"-l", allowedUser})
	}

	if loginName == "" {
		currentUser, _ := user.Current()
		loginName = currentUser.Username
	}

	return loginName
}

func updateRequestExtensions(requestExtensions *signer.Extensions, sshOptions *openssh.Options) {
	if !requestExtensions.AgentForwarding && sshOptions.ForwardAgent {
		requestExtensions.AgentForwarding = true
	} else if requestExtensions.AgentForwarding && sshOptions.NoForwardAgent {
		requestExtensions.AgentForwarding = false
	}

	if !requestExtensions.PortForwarding &&
		(sshOptions.ProxyJump != "" || sshOptions.DynamicForward != nil || sshOptions.LocalForward != nil || sshOptions.RemoteForward != nil) {
		requestExtensions.PortForwarding = true
	}

	if !requestExtensions.NoPTY &&
		(sshOptions.NoPTY || (sshOptions.ForcePTY == nil && len(sshOptions.Positional.RemoteCommand) > 0)) {
		requestExtensions.NoPTY = true
	}

	if !requestExtensions.X11Forwarding && sshOptions.ForwardX11 {
		requestExtensions.X11Forwarding = true
	}
}
