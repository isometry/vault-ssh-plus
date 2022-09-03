package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/isometry/vault-ssh-plus/openssh"
	"github.com/isometry/vault-ssh-plus/signer"
	"github.com/jessevdk/go-flags"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	options struct {
		Signer  signer.Options  `group:"Vault SSH key signing Options"`
		OpenSSH openssh.Options `group:"OpenSSH ssh(1) Options" hidden:"yes"`
		Version func()          `long:"version" description:"Show version"`
	}
)

func showVersion() {
	fmt.Printf("vault-ssh-plus v%s (%s), %s\n", version, commit, date)
	os.Exit(0)
}

func init() {
	options.Version = showVersion

	parser := flags.NewParser(&options, flags.Default)
	parser.Usage = "[options] destination [command]"
	if _, err := parser.ParseArgs(os.Args[1:]); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		// DisableTimestamp:       true,
		PadLevelText: false,
	})
	if len(options.OpenSSH.Verbose) > 0 {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	os.Exit(processCommand())
}

func processCommand() int {
	var (
		vaultClient signer.Client
		sshClient   openssh.Client
		err         error
	)

	sshClient.Args, err = signer.ParseArgs(&vaultClient, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	userOverridden := overrideUser(&vaultClient, &sshClient)
	if userOverridden {
		log.Info("remote user overridden by vault role")
	}

	if err := sshClient.ParseConfig(); err != nil {
		log.Fatal("failed to parse ssh configuration: ", err)
	}

	// if we have already have a Control Connection, use it
	controlConnection := sshClient.ControlConnection()

	if !controlConnection && options.OpenSSH.ControlCommand != "exit" {
		updateRequestExtensions(&vaultClient.Options.Extensions, &sshClient.Extensions)

		signedKey, err := vaultClient.GetSignedKey(sshClient.User)
		if err != nil {
			log.Fatal("failed to get signed key: ", err)
		}

		if err := sshClient.SetSignedKey(signedKey); err != nil {
			log.Fatal("invalid certificate: ", err)
		}

		certificateFile, err := sshClient.WriteCertificateFile(
			filepath.Dir(vaultClient.Options.PublicKey),
			fmt.Sprintf("signed_%s@*", filepath.Base(vaultClient.Options.PublicKey)),
		)
		if err != nil {
			log.Fatal("failed to write signed key to file: ", err)
		}

		// ensure the signedKeyFile is deleted if we're killed
		setupExitHandler(certificateFile)
		defer os.Remove(certificateFile)

		sshClient.PrependArgs([]string{"-o", fmt.Sprintf("CertificateFile=%s", certificateFile)})
		// sshClient.PrependArgs([]string{"-i", signedKeyFile})
	}

	log.WithFields(log.Fields{
		"ssh-args":                 sshClient.Args,
		"reuse-control-connection": controlConnection,
	}).Debug()

	if err := sshClient.Connect(controlConnection); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode()
		} else {
			return 999
		}
	}

	return 0
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

func overrideUser(vaultClient *signer.Client, sshClient *openssh.Client) bool {
	// if the role only allows a single, fixed user, use it
	if user := vaultClient.GetAllowedUser(); user != "" {
		sshClient.User = user
		sshClient.PrependArgs([]string{"-l", user})
		return true
	}

	return false
}

func updateRequestExtensions(reqExt *signer.Extensions, sshExt *openssh.Extensions) {
	if !reqExt.AgentForwarding && sshExt.AgentForwarding {
		reqExt.AgentForwarding = true
	}

	if !reqExt.NoPTY && sshExt.NoPTY {
		reqExt.NoPTY = true
	}

	if !reqExt.PortForwarding && sshExt.PortForwarding {
		reqExt.PortForwarding = true
	}

	if !reqExt.X11Forwarding && sshExt.X11Forwarding {
		reqExt.X11Forwarding = true
	}
}
