package agent

import (
	"io"
	"net"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type InternalAgent struct {
	keyring    agent.Agent
	socketDir  string
	socketFile string
	listener   net.Listener
	stop       chan bool
	stopped    chan bool
}

func NewInternalAgent() (ia *InternalAgent, err error) {
	socketDir, err := os.MkdirTemp("", "vssh-agent.*")
	if err != nil {
		return
	}

	ia = &InternalAgent{
		keyring:    agent.NewKeyring(),
		socketDir:  socketDir,
		socketFile: filepath.Join(socketDir, "agent.sock"),
		stop:       make(chan bool),
		stopped:    make(chan bool),
	}

	ia.listener, err = net.Listen("unix", ia.socketFile)
	if err != nil {
		return nil, err
	}

	go ia.run()
	return ia, nil
}

func (ia *InternalAgent) run() {
	defer close(ia.stopped)
	for {
		select {
		case <-ia.stop:
			return
		default:
			conn, err := ia.listener.Accept()
			if err != nil {
				select {
				case <-ia.stop:
					return
				default:
					log.Fatalf("could not accept connection to agent %v", err)
					continue
				}
			}
			defer conn.Close()
			go func(c io.ReadWriter) {
				err := agent.ServeAgent(ia.keyring, c)
				if err != nil && !errors.Is(err, io.EOF) {
					log.Printf("could not serve ssh agent %v", err)
				}
			}(conn)
		}
	}
}

func (ia *InternalAgent) AddSignedKeyPair(privateKeyStr string, signedKeyStr string) (err error) {
	privateKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyStr))
	if err != nil {
		return errors.Wrap(err, "failed to parse private key")
	}

	signedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKeyStr))
	if err != nil {
		return errors.Wrap(err, "failed to parse signed public key")
	}

	return ia.keyring.Add(agent.AddedKey{
		PrivateKey:  privateKey,
		Certificate: signedKey.(*ssh.Certificate),
	})
}

func (ia *InternalAgent) Stop() {
	close(ia.stop)
	ia.listener.Close()
	<-ia.stopped
	os.RemoveAll(ia.socketDir)
}

func (ia *InternalAgent) SocketFile() string {
	return ia.socketFile
}
