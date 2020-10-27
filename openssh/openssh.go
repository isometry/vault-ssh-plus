package openssh

import (
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"
)

type Client struct {
	Args          []string
	Options       Options
	SignedKey     string
	SignedKeyFile string
}

// Options for https://man.openbsd.org/ssh.1
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
	ControlCommand        string     `short:"O" description:"Send control command"`
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
	Exec                  bool       `long:"exec" env:"VAULT_SSH_EXEC" description:"Call ssh via execve(2)"`
	Hostname              string
}

// Positional arguments for https://man.openbsd.org/ssh.1
type Positional struct {
	Destination   string   `positional-arg-name:"destination" required:"true"`
	RemoteCommand []string `positional-arg-name:"command"`
}

// ParseArgs parses arguments intended for https://man.openbsd.org/ssh.1
func ParseArgs(args []string) (Client, []string, error) {
	var o Client

	o.Args = args

	parser := flags.NewParser(&o.Options, flags.PassDoubleDash|flags.IgnoreUnknown)
	unparsedArgs, err := parser.ParseArgs(args)
	if err != nil {
		return Client{}, nil, err
	}

	if err := o.ParseDestination(o.Options.Positional.Destination); err != nil {
		return Client{}, nil, err
	}
	if err := o.ParseOptions(o.Options.Option, "="); err != nil {
		return Client{}, nil, err
	}

	return o, unparsedArgs, nil
}

// ParseDestination parses the `destination` argument as an `ssh://` scheme URI and updates options according to what it finds
func (c *Client) ParseDestination(destination string) error {
	if destination[0:6] != "ssh://" {
		destination = "ssh://" + destination
	}
	uri, err := url.Parse(destination)
	if err != nil {
		return err
	}

	if uri.User.Username() != "" {
		c.Options.LoginName = uri.User.Username()
	}

	if uri.Port() != "" {
		port, err := strconv.ParseUint(uri.Port(), 10, 16)
		if err != nil {
			log.Print("[WARN] error parsing port from destination: ", err)
		} else {
			c.Options.Port = uint16(port)
		}
	}
	c.Options.Hostname = uri.Hostname()

	return nil
}

// ParseOptions parses ssh_config options of the form `key[separator]value` and updates other options accordingly
func (c *Client) ParseOptions(options []string, separator string) error {
	for _, option := range options {
		split := strings.Split(option, separator)
		key, value := split[0], strings.Join(split[1:], separator)
		switch key {
		case "User":
			if c.Options.LoginName == "" {
				c.Options.LoginName = value
			}
		case "Port":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return err
			}
			c.Options.Port = uint16(port)
		case "DynamicForward":
			c.Options.DynamicForward = append(c.Options.DynamicForward, value)
		case "LocalForward":
			c.Options.LocalForward = append(c.Options.LocalForward, value)
		case "RemoteForward":
			c.Options.RemoteForward = append(c.Options.RemoteForward, value)
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

// SetSignedKey sets the Client's signed key
func (c *Client) SetSignedKey(key string) {
	c.SignedKey = key
}

// WriteSignedKeyFile updates the signed key at path/name
func (c *Client) WriteSignedKeyFile(path, name string) (string, error) {
	if strings.Contains(name, "*") {
		signedKeyFile, err := ioutil.TempFile(path, name)
		if err != nil {
			return "", err
		}
		if _, err := signedKeyFile.Write([]byte(c.SignedKey)); err != nil {
			return "", err
		}

		if err := signedKeyFile.Close(); err != nil {
			return "", err
		}

		return signedKeyFile.Name(), nil
	} else {
		signedKeyFileName := filepath.Join(path, name)
		if err := ioutil.WriteFile(signedKeyFileName, []byte(c.SignedKey), 0600); err != nil {
			return "", err
		}
		return signedKeyFileName, nil
	}
}

// Connect establishes the ssh client connection
func (c *Client) Connect() error {
	if c.Options.Exec {
		sshPath, err := exec.LookPath(clientBinary)
		if err != nil {
			return err
		}

		return syscall.Exec(sshPath, append([]string{clientBinary}, c.Args...), os.Environ())
	} else {
		cmd := exec.Command(clientBinary, c.Args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

		return cmd.Run()
	}
}
