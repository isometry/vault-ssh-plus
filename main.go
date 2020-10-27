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

var options struct {
	Signer  signer.Options  `group:"Vault SSH key signing Options"`
	OpenSSH openssh.Options `group:"OpenSSH ssh(1) Options" hidden:"yes"`
	Version func()          `long:"version" group:"Help" description:"show version"`
}

func main() {
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
			fmt.Println(err)
			os.Exit(1)
		}
	}

	vaultClient, unparsedArgs, err := signer.ParseArgs(os.Args[1:])
	if err != nil {
		log.Fatal("[ERROR] parsing vault options: ", err)
	}

	sshClient, _, err := openssh.ParseArgs(unparsedArgs)
	if err != nil {
		log.Fatal("[ERROR] parsing ssh options: ", err)
	}

	if sshClient.Options.LoginName == "" {
		currentUser, _ := user.Current()
		sshClient.Options.LoginName = currentUser.Username
	}

	controlConnection := sshClient.ControlConnection()

	if !controlConnection && sshClient.Options.ControlCommand != "exit" {
		if !vaultClient.Options.Extensions.PortForwarding &&
			(sshClient.Options.ProxyJump != "" ||
				sshClient.Options.DynamicForward != nil ||
				sshClient.Options.LocalForward != nil ||
				sshClient.Options.RemoteForward != nil) {
			vaultClient.Options.Extensions.PortForwarding = true
		}

		if !vaultClient.Options.Extensions.NoPTY &&
			(sshClient.Options.NoPTY ||
				(sshClient.Options.ForcePTY == nil && len(sshClient.Options.Positional.RemoteCommand) > 0)) {
			vaultClient.Options.Extensions.NoPTY = true
		}

		if !vaultClient.Options.Extensions.X11Forwarding && sshClient.Options.ForwardX11 {
			vaultClient.Options.Extensions.X11Forwarding = true
		}

		signedKey, err := vaultClient.GetSignedKey(sshClient.Options.LoginName)
		if err != nil {
			log.Fatal("[ERROR] failed to get signed key: ", err)
		}

		sshClient.SetSignedKey(signedKey)

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
	signal.Notify(s, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-s
		_ = os.Remove(fn)
		os.Exit(0)
	}()
}
