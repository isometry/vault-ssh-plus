package main

import (
	"fmt"
	"log"
	"os"
	"os/user"

	"github.com/isometry/vault-ssh-client/openssh"
	"github.com/isometry/vault-ssh-client/signer"
	"github.com/jessevdk/go-flags"
)

var (
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
		fmt.Printf("vault-ssh-client v%s (%s), %s\n", version, commit, date)
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

	vaultClient, unparsedArgs := signer.ParseArgs(os.Args[1:])
	sshClient, _ := openssh.ParseArgs(unparsedArgs)

	if sshClient.Options.LoginName == "" {
		currentUser, _ := user.Current()
		sshClient.Options.LoginName = currentUser.Username
	}

	controlConnection := sshClient.ControlConnection()

	if !controlConnection {
		if !vaultClient.Options.PTY && len(sshClient.Options.ForcePTY) > 0 {
			vaultClient.Options.PTY = true
		}
		if !vaultClient.Options.PortForwarding &&
			(sshClient.Options.JumpHost != "" ||
				sshClient.Options.DynamicPortForwarding != "" ||
				sshClient.Options.LocalForwarding != nil ||
				sshClient.Options.RemoteForwarding != nil) {
			vaultClient.Options.PortForwarding = true
		}
		signedKey := vaultClient.SignKey(sshClient.Options.LoginName)
		defer os.Remove(signedKey)
		sshClient.PrependArgs([]string{"-i", signedKey})
	}

	log.Printf("[DEBUG] %v %v\n", sshClient.Args, controlConnection)

	if err := sshClient.Connect(); err != nil {
		log.Fatal("failed to connect: ", err)
	}
}
