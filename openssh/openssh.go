package openssh

import (
	"log"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/jessevdk/go-flags"
)

type Client struct {
	Args    []string
	Options Options
}

// Options for https://man.openbsd.org/ssh.1
type Options struct {
	IPv4Only               bool       `short:"4" description:"Enable IPv4 only"`
	IPv6Only               bool       `short:"6" description:"Enable IPv6 only"`
	AgentForwarding        bool       `short:"A" description:"Enable agent forwarding"`
	NoAgentForwarding      bool       `short:"a" description:"Disable agent forwarding"`
	BindInterface          string     `short:"B" description:"Bind interface"`
	BindAddress            string     `short:"b" description:"Bind address"`
	Compression            bool       `short:"C" description:"Enable compression"`
	CipherSpec             string     `short:"c" description:"Cipher specification"`
	DynamicPortForwarding  string     `short:"D" description:"Dynamic port forwarding"`
	LogFile                string     `short:"E" description:"Log file"`
	EscapeChar             string     `short:"e" description:"Escape character"`
	ConfigFile             string     `short:"F" description:"Config file"`
	Background             bool       `short:"f" description:"Background before command execution"`
	PrintConfig            bool       `short:"G" description:"Print Configuration and Exit"`
	AllowRemoteToLocal     bool       `short:"g" description:"Allow remote hosts to connect to local forwarded ports"`
	PKCS11                 string     `short:"I" description:"PKCS#11 shared library"`
	IdentityFile           []string   `short:"i" description:"Identity file"`
	JumpHost               string     `short:"J" description:"Jump host"`
	Kerberos               bool       `short:"K" description:"Enable GSSAPI auth and forwarding"`
	NoKerberosForwarding   bool       `short:"k" description:"Disable GSSAPI forwarding"`
	LocalForwarding        []string   `short:"L" description:"Local port forwarding"`
	LoginName              string     `short:"l" description:"Login name"`
	ControlMaster          []bool     `short:"M" description:"Master moder for connection sharing"`
	MacSpec                string     `short:"m" description:"Mac Specification"`
	NoRemoteCommand        bool       `short:"N" description:"Do not execute a remote command"`
	NullStdin              bool       `short:"n" description:"Redirect stdin from /dev/null"`
	ControlCommand         string     `short:"O" description:"Send control command"`
	Option                 []string   `short:"o" description:"Override configuration option"`
	Port                   uint16     `short:"p" default:"22" description:"Port"`
	QueryOption            string     `short:"Q" description:"Query supported algorithms"`
	Quiet                  bool       `short:"q" description:"Quiet mode"`
	RemoteForwarding       []string   `short:"R" description:"Remote port forwarding"`
	ControlPath            string     `short:"S" description:"Control socket path"`
	Subsystem              bool       `short:"s" description:"Requent remote subsystem"`
	NoPTY                  bool       `short:"T" description:"Disable pseudo-terminal allocation"`
	ForcePTY               []bool     `short:"t" description:"Force pseudo-terminal allocation"`
	Version                bool       `short:"V" description:"Display version"`
	Verbose                []bool     `short:"v" description:"Verbose mode"`
	StdinStdoutforwarding  string     `short:"W" description:"Forward stdin+stdout to remote host:port"`
	TunnelDeviceForwarding string     `short:"w" description:"Request tunnel device forwarding"`
	X11Forwarding          bool       `short:"X" description:"Enable X11 forwarding"`
	NoX11Forwarding        bool       `short:"x" description:"Disable X11 forwarding"`
	TrustedX11Forwarding   bool       `short:"Y" description:"Enable trusted X11 forwarding"`
	Syslog                 bool       `short:"y" description:"Log to syslog(3)"`
	Positional             Positional `positional-args:"yes"`
	Host                   string
}

// Positional arguments for https://man.openbsd.org/ssh.1
type Positional struct {
	Destination string   `positional-arg-name:"destination" required:"true"`
	Command     []string `positional-arg-name:"command"`
}

// ParseArgs parses arguments intended for https://man.openbsd.org/ssh.1
func ParseArgs(args []string) Client {
	var o Client

	o.Args = args

	_, err := flags.ParseArgs(&o.Options, args)
	if err != nil {
		log.Fatal("error parsing ssh args: ", err)
	}

	uri, err := url.Parse(o.Options.Positional.Destination)
	if err != nil {
		log.Fatal("error parsing ssh destination: ", err)
	}
	if uri.User.Username() != "" {
		o.Options.LoginName = uri.User.Username()
	}
	if uri.Port() != "" {
		port, err := strconv.ParseUint(uri.Port(), 10, 16)
		if err != nil {
			log.Fatal("error parsing ssh port from scheme: ", err)
		}
		o.Options.Port = uint16(port)
	}
	o.Options.Host = uri.Hostname()
	return o
}

// ControlConnection checks for the existence of an active control connection
func (c *Client) ControlConnection() bool {
	cmdArgs := append([]string{"-O", "check"}, c.Args...)
	cmd := exec.Command(clientBinary, cmdArgs...)
	_, err := cmd.Output()
	return (err == nil)
}

func (c *Client) PrependArgs(args []string) {
	c.Args = append(args, c.Args...)
}

// Connect establishes the ssh client connection
func (c *Client) Connect(withWithExec bool) error {
	if withWithExec {
		sshPath, err := exec.LookPath(clientBinary)
		if err != nil {
			log.Fatal("ssh not found in PATH: ", err)
		}

		return syscall.Exec(sshPath, append([]string{clientBinary}, c.Args...), os.Environ())
	} else {
		cmd := exec.Command(clientBinary, c.Args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

		return cmd.Run()
	}
}
