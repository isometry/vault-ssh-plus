package shell

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type Client struct {
	User     string
	Hostname string
	Port     uint16
	Signer   *ssh.Signer
}

func NewClient(destination string, signer *ssh.Signer) (*Client, error) {
	client := Client{}
	err := client.ParseDestination(destination)
	if err != nil {
		return nil, err
	}

	// XXX: add flag to control whether agent is used
	if signer != nil {
		client.Signer = signer
	} else {
		agentSigners, err := GetAgentSigners()
		if err != nil {
			return nil, err
		}

		client.Signer = &agentSigners[0]
	}

	/*
		publicKey := privateKey.PublicKey()

		certificate, ok := publicKey.(*ssh.Certificate)
		if !ok {
			log.Fatal("failed to cast public key to certificate: ", err)
		}

		certSigner, err := ssh.NewCertSigner(certificate, privateKey)
		if err != nil {
			log.Fatal("failed to create cert signer: ", err)
		}
	*/

	return &client, nil
}

// ParseDestination parses the `destination` argument as an `ssh://` scheme URI and updates options according to what it finds
func (c *Client) ParseDestination(destination string) error {
	log.Println("Parsing destination: ", destination)
	if len(destination) < 7 || destination[0:6] != "ssh://" {
		destination = "ssh://" + destination
	}
	uri, err := url.Parse(destination)
	if err != nil {
		return err
	}

	if uri.User.Username() != "" {
		c.User = uri.User.Username()
	}

	if uri.Port() != "" {
		port, err := strconv.ParseUint(uri.Port(), 10, 16)
		if err != nil {
			return err
		}
		c.Port = uint16(port)
	} else {
		c.Port = 22
	}
	c.Hostname = uri.Hostname()

	return nil
}

func GetAgentSigners() ([]ssh.Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	agentConn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	agentClient, err := agent.NewClient(agentConn), nil
	if err != nil {
		return nil, err
	}

	agentKeys, err := agentClient.List()
	if err != nil {
		return nil, err
	}
	if len(agentKeys) == 0 {
		return nil, fmt.Errorf("ssh-agent is empty")
	}

	agentSigners, err := agentClient.Signers()
	if err != nil {
		return nil, err
	}
	if len(agentSigners) == 0 {
		return nil, fmt.Errorf("ssh-agent is empty")
	}

	return agentSigners, nil

}

// Connect opens shell for user@destination
// TODO: think about allowing allow to pass publicKey in as []byte
func (c *Client) Connect(sshHostKeyCallback ssh.HostKeyCallback) error {
	hostKeyCallback := sshHostKeyCallback
	if hostKeyCallback == nil {
		// Non-production only
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(*c.Signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	hostPort := fmt.Sprintf("%s:%d", c.Hostname, c.Port)
	clientConn, err := ssh.Dial("tcp", hostPort, config)
	if err != nil {
		log.Fatal("failed to dial connection: ", err)
	}
	defer clientConn.Close()

	session, err := clientConn.NewSession()
	if err != nil {
		log.Fatal("failed to create session: ", err)
	}
	defer session.Close()

	/*
		fd := int(os.Stdin.Fd())
		state, err := terminal.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("terminal make raw: %s", err)
		}
		defer terminal.Restore(fd, state)

		term := os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}

		w, h, err := terminal.GetSize(fd)
		if err != nil {
			return fmt.Errorf("terminal get size: %s", err)
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 57600,
			ssh.TTY_OP_OSPEED: 57600,
		}

		if err := session.RequestPty(term, h, w, modes); err != nil {
			log.Fatal("failed to request pty: ", err)
		}

		session.Stdin, session.Stdout, session.Stderr = os.Stdin, os.Stdout, os.Stderr

		if err := session.Shell(); err != nil {
			log.Fatal("failed to open shell: ", err)
		}
	*/

	restorer, err := OpenShell(session)
	defer restorer()
	if err != nil {
		return err
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		return fmt.Errorf("ssh: %s", err)
	}

	return nil
}

func OpenShell(session *ssh.Session) (func() error, error) {
	restorer := func() error { return nil }

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return restorer, fmt.Errorf("terminal make raw: %s", err)
	}
	restorer = func() error {
		return terminal.Restore(fd, state)
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return restorer, fmt.Errorf("terminal get size: %s", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 57600,
		ssh.TTY_OP_OSPEED: 57600,
	}

	if err := session.RequestPty(term, h, w, modes); err != nil {
		log.Fatal("failed to request pty: ", err)
	}

	session.Stdin, session.Stdout, session.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := session.Shell(); err != nil {
		log.Fatal("failed to open shell: ", err)
	}

	return restorer, nil

}
