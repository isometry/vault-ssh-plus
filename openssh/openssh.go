package openssh

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	Args              []string
	HostConfig        []string
	User              string
	Hostname          string
	Extensions        Extensions
	CertificateString string
	CertificateFile   string
	CertificateObject *ssh.Certificate
}

// Options for https://man.openbsd.org/ssh.1; parsed simply to provide accurate Destination and RemoteCommand
type Options struct {
	IPv4Only              bool       `short:"4" description:"Enable IPv4 only"`
	IPv6Only              bool       `short:"6" description:"Enable IPv6 only"`
	ForwardAgent          bool       `short:"A" description:"Enable agent forwarding"`
	NoForwardAgent        bool       `short:"a" description:"Disable agent forwarding"`
	BindInterface         string     `short:"B" description:"Bind interface"`
	BindAddress           string     `short:"b" description:"Bind address"`
	Compression           bool       `short:"C" description:"Enable compression"`
	CipherSpec            string     `short:"c" description:"Cipher specification"`
	DynamicForward        []string   `short:"D" description:"Dynamic port forwarding"`
	LogFile               string     `short:"E" description:"Log file"`
	EscapeChar            string     `short:"e" description:"Escape character"`
	ConfigFile            string     `short:"F" description:"Config file"`
	Background            bool       `short:"f" description:"Background before command execution"`
	PrintConfig           bool       `short:"G" description:"Print Configuration and Exit"`
	AllowRemoteToLocal    bool       `short:"g" description:"Allow remote hosts to connect to local forwarded ports"`
	PKCS11                string     `short:"I" description:"PKCS#11 shared library"`
	IdentityFile          []string   `short:"i" description:"Identity file"`
	ProxyJump             string     `short:"J" description:"Jump host"`
	GSSAPIAuthentication  bool       `short:"K" description:"Enable GSSAPI auth and forwarding"`
	NoGSSAPIDelegation    bool       `short:"k" description:"Disable GSSAPI forwarding"`
	LocalForward          []string   `short:"L" description:"Local port forwarding"`
	LoginName             string     `short:"l" description:"Login name"`
	ControlMaster         []bool     `short:"M" description:"Master moder for connection sharing"`
	MacSpec               string     `short:"m" description:"Mac Specification"`
	NoRemoteCommand       bool       `short:"N" description:"Do not execute a remote command"`
	NullStdin             bool       `short:"n" description:"Redirect stdin from /dev/null"`
	ControlCommand        string     `short:"O" choice:"check" choice:"forward" choice:"cancel" choice:"exit" choice:"stop" description:"Send control command"`
	Option                []string   `short:"o" description:"Override configuration option"`
	Port                  uint16     `short:"p" default:"22" description:"Port"`
	QueryOption           string     `short:"Q" description:"Query supported algorithms"`
	Quiet                 bool       `short:"q" description:"Quiet mode"`
	RemoteForward         []string   `short:"R" description:"Remote port forwarding"`
	ControlPath           string     `short:"S" description:"Control socket path"`
	Subsystem             bool       `short:"s" description:"Requent remote subsystem"`
	NoPTY                 bool       `short:"T" description:"Disable pseudo-terminal allocation"`
	ForcePTY              []bool     `short:"t" description:"Force pseudo-terminal allocation"`
	Version               bool       `short:"V" description:"Display version"`
	Verbose               []bool     `short:"v" description:"Verbose mode"`
	StdinStdoutforwarding string     `short:"W" description:"Forward stdin+stdout to remote host:port"`
	TunnelDevice          string     `short:"w" description:"Request tunnel device forwarding"`
	ForwardX11            bool       `short:"X" description:"Enable X11 forwarding"`
	NoForwardX11          bool       `short:"x" description:"Disable X11 forwarding"`
	ForwardX11Trusted     bool       `short:"Y" description:"Enable trusted X11 forwarding"`
	Syslog                bool       `short:"y" description:"Log to syslog(3)"`
	Positional            Positional `positional-args:"yes"`
}

// Positional arguments for https://man.openbsd.org/ssh.1
type Positional struct {
	Destination   string   `positional-arg-name:"destination" required:"true"`
	RemoteCommand []string `positional-arg-name:"command"`
}

type Extensions struct {
	AgentForwarding bool
	PortForwarding  bool
	NoPTY           bool
	UserRC          bool
	X11Forwarding   bool
}

// ParseConfig uses `ssh -G` to obtain a fully processed ssh_config(5), parse the result and update configuration accordingly
func (c *Client) ParseConfig() error {
	cmdArgs := append([]string{"-G"}, c.Args...)
	cmd := exec.Command(clientBinary, cmdArgs...)

	output, err := cmd.Output()
	if err != nil {
		return errors.Wrap(err, "getting ssh_config")
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		split := strings.SplitN(scanner.Text(), " ", 2)
		key := strings.ToLower(split[0])
		value := ""
		if len(split) == 2 {
			value = split[1]
		}

		switch key {
		case "user":
			c.User = value
		case "hostname":
			c.Hostname = value
		case "dynamicforward":
			c.Extensions.PortForwarding = true
		case "forwardagent":
			if value == "yes" {
				c.Extensions.AgentForwarding = true
			}
		case "forwardx11":
			if value == "yes" {
				c.Extensions.X11Forwarding = true
			}
		case "forwardx11trusted":
			if value == "yes" {
				c.Extensions.X11Forwarding = true
			}
		case "localforward":
			c.Extensions.PortForwarding = true
		case "remoteforward":
			c.Extensions.PortForwarding = true
		case "requesttty":
			if value == "false" {
				c.Extensions.NoPTY = true
			}
		}
	}

	return nil
}

// ControlConnection checks for the existence of an active control connection
func (c *Client) ControlConnection() bool {
	cmdArgs := append([]string{"-O", "check"}, c.Args...)
	cmd := exec.Command(clientBinary, cmdArgs...)
	_, err := cmd.Output()
	return (err == nil)
}

// PrependArgs prepends the specified arguments to the list to be passed to ssh(1)
func (c *Client) PrependArgs(args []string) {
	c.Args = append(args, c.Args...)
}

// SetSignedKey sets Client.SignedKey
func (c *Client) SetSignedKey(key string) (err error) {
	c.CertificateString = key
	c.CertificateObject, err = ParseSignedKey(key)

	return
}

// WriteCertificateFile writes an ephemeral certificate file to disk
func (c *Client) WriteCertificateFile() (string, error) {
	signedKeyFile, err := os.CreateTemp("", "vssh-cert.*")
	if err != nil {
		return "", errors.Wrap(err, "creating temporary certificate file")
	}
	if _, err := signedKeyFile.Write([]byte(c.CertificateString)); err != nil {
		return "", errors.Wrap(err, "writing certificate to temporary file")
	}

	if err := signedKeyFile.Close(); err != nil {
		return "", errors.Wrap(err, "closing temporary certificate file")
	}
	log.Debugf("certificate file written to %q", signedKeyFile.Name())

	return signedKeyFile.Name(), nil
}

// Connect establishes the ssh client connection
func (c *Client) Connect(connectionSharing bool) error {
	// save some memory if we're connection sharing
	if connectionSharing {
		sshPath, err := exec.LookPath(clientBinary)
		if err != nil {
			return err
		}

		return syscall.Exec(sshPath, append([]string{clientBinary}, c.Args...), os.Environ())
	}

	cmd := exec.Command(clientBinary, c.Args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	return cmd.Run()
}

func ParseSignedKey(certificateString string) (*ssh.Certificate, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificateString))
	if err != nil {
		return nil, err
	}

	certificate, ok := publicKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("invalid certificate")
	}

	return certificate, nil
}
