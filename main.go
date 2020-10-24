package main

import (
	"log"
	"os"
	"os/user"

	"github.com/isometry/vault-ssh-client/openssh"
	"github.com/isometry/vault-ssh-client/signer"
	"github.com/jessevdk/go-flags"
)

var options struct {
	Signer  signer.Options  `group:"Vault SSH key signing options"`
	OpenSSH openssh.Options `group:"OpenSSH ssh(1) options" hidden:"yes"`
}

func main() {
	parser := flags.NewParser(&options, flags.HelpFlag|flags.PassDoubleDash)
	if _, err := parser.ParseArgs(os.Args[1:]); err != nil {
		log.Fatal("error parsing arguments: ", err)
	}

	sshClient, unparsedArgs := openssh.ParseArgs(os.Args[1:])

	if sshClient.Options.LoginName == "" {
		currentUser, _ := user.Current()
		sshClient.Options.LoginName = currentUser.Username
	}

	controlConnection := sshClient.ControlConnection()

	if !controlConnection {
		vaultClient, _ := signer.ParseArgs(unparsedArgs)
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
