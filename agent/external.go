package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
)

var sshKeyTypeMap = map[string][]string{
	"rsa":     {ssh.KeyAlgoRSA},
	"ec":      {ssh.KeyAlgoECDSA256, ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	"ed25519": {ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519},
	"sk":      {ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoSKED25519},
}

var supportedKeyTypes = []string{
	ssh.KeyAlgoRSA,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoSKED25519,
}

func GetBestPublicKey(preferredType string) (publicKey []byte, err error) {
	prefKeyTypes, ok := sshKeyTypeMap[preferredType]
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
		if slices.Contains(prefKeyTypes, keyType) {
			bestKey = key
			break
		}
	}
	if bestKey == nil {
		return nil, errors.New("no viable key found in external agent")
	}
	if !slices.Contains(prefKeyTypes, bestKey.Type()) {
		log.Infof("no key of type %q found, falling back to first key of type %q", preferredType, bestKey.Type())
	}

	return []byte(bestKey.String()), nil
}
