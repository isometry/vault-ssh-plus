package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
)

var sshKeyTypeMap = map[string]string{
	"rsa":     "ssh-rsa",
	"ec":      "ssh-ecdsa",
	"ed25519": "ssh-ed25519",
}

var supportedKeyTypes = []string{
	"ssh-rsa",
	"ssh-ecdsa",
	"ssh-ed25519",
}

func GetBestPublicKey(preferredType string) (publicKey []byte, err error) {
	prefKeyType, ok := sshKeyTypeMap[preferredType]
	if !ok {
		return nil, fmt.Errorf("invalid key type: %q", preferredType)
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		currentUser, err := user.Current()
		if err != nil {
			return nil, err
		}
		sock = fmt.Sprintf("%s/.ssh/agent.sock", currentUser.HomeDir)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return
	}
	defer conn.Close()

	keyring := agent.NewClient(conn)

	keys, err := keyring.List()
	if err != nil {
		return
	}

	var bestKey *agent.Key
	for _, key := range keys {
		keyType := key.Type()
		if bestKey == nil && slices.Contains(supportedKeyTypes, keyType) {
			bestKey = key
		}
		if keyType == prefKeyType {
			bestKey = key
			break
		}
	}
	if bestKey == nil {
		return nil, errors.New("no viable key found in external agent")
	}
	if bestKey.Type() != prefKeyType {
		log.Infof("no key of type %q found, falling back to first key of type %q", preferredType, bestKey.Type())
	}

	return []byte(bestKey.String()), nil
}
