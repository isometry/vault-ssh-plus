package signer

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/vault/api"
	"github.com/isometry/vault-ssh-plus/agent"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	API        *api.Client
	RoleConfig map[string]interface{}
	Options    Options
	PublicKey  []byte
	SignedKey  string
}

// Options define signer-specific flags
type Options struct {
	Mode       string     `long:"mode" choice:"sign" choice:"issue" default:"issue" env:"VAULT_SSH_MODE" description:"Mode"`
	Type       string     `long:"type" choice:"rsa" choice:"ec" choice:"ed25519" choice:"sk" default:"ed25519" env:"VAULT_SSH_KEY_TYPE" description:"Key type or preference for 'sign' mode"`
	Bits       uint       `long:"bits" choice:"0" choice:"2048" choice:"3072" choice:"4096" choice:"256" choice:"384" choice:"521" default:"0" env:"VAULT_SSH_KEY_BITS" description:"Key bits for 'issue' mode"`
	Path       string     `long:"path" default:"ssh" env:"VAULT_SSH_PATH" description:"Vault SSH mountpoint"`
	Role       string     `long:"role" env:"VAULT_SSH_ROLE" description:"Vault SSH role (default: <ssh-username>)"`
	TTL        uint       `long:"ttl" default:"300" env:"VAULT_SSH_TTL" description:"Vault SSH certificate TTL"`
	PublicKey  string     `short:"P" long:"public-key" env:"VAULT_SSH_PUBLIC_KEY" description:"Path to preferred public key for 'sign' mode"`
	Extensions Extensions `group:"Certificate Extensions"`
}

// Extensions control what certificate extensions are required for the signed key
type Extensions struct {
	Default         bool `long:"default-extensions" env:"VAULT_SSH_DEFAULT_EXTENSIONS" description:"Disable automatic extension calculation and request signer-default extensions"`
	AgentForwarding bool `long:"agent-forwarding" env:"VAULT_SSH_AGENT_FORWARDING" description:"Force permit-agent-forwarding extension"`
	PortForwarding  bool `long:"port-forwarding" env:"VAULT_SSH_PORT_FORWARDING" description:"Force permit-port-forwarding extension"`
	NoPTY           bool `long:"no-pty" env:"VAULT_SSH_NO_PTY" description:"Force disable permit-pty extension"`
	UserRC          bool `long:"user-rc" env:"VAULT_SSH_USER_RC" description:"Enable permit-user-rc extension"`
	X11Forwarding   bool `long:"x11-forwarding" env:"VAULT_SSH_X11_FORWARDING" description:"Force permit-X11-forwarding extension"`
}

func ParseArgs(client *Client, args []string) (unparsedArgs []string, err error) {
	var options Options

	parser := flags.NewParser(&options, flags.PassDoubleDash|flags.IgnoreUnknown)
	unparsedArgs, err = parser.ParseArgs(args)
	if err != nil {
		return nil, errors.Wrap(err, "parsing arguments")
	}

	// explicitly setting a public key forces sign mode
	if options.PublicKey != "" {
		options.Mode = "sign"
	}

	if options.Mode == "issue" && options.Type == "sk" {
		return nil, errors.New("key type 'sk' incompatible with 'issue' mode")
	}

	if options.Mode == "sign" {
		if strings.HasPrefix(options.PublicKey, "~/") {
			currentUser, _ := user.Current()
			if err != nil {
				return nil, errors.Wrap(err, "getting current user")
			}

			options.PublicKey = filepath.Join(currentUser.HomeDir, options.PublicKey[2:])
		}

		var publicKey []byte
		if options.PublicKey != "" {
			log.Debug("public key option set, reading file")
			publicKey, err = ioutil.ReadFile(options.PublicKey)
			if err != nil {
				return nil, errors.Wrap(err, "reading public key file")
			}
		} else {
			log.Debug("public key option NOT set, reading agent")
			publicKey, err = agent.GetBestPublicKey(options.Type)
			if err != nil {
				return nil, errors.Wrap(err, "finding agent key")
			}
		}

		if err := client.SetPublicKey(publicKey); err != nil {
			return nil, errors.Wrap(err, "setting public key")
		}
	}

	client.API, err = GetVaultClient()
	if err != nil {
		return nil, errors.Wrap(err, "initializing Vault client")
	}

	client.Options = options

	return unparsedArgs, nil
}

func (c *Client) SetPublicKey(publicKey []byte) (err error) {
	// publicKey, err := ioutil.ReadFile(fn)
	// if err != nil {
	// 	return errors.Wrap(err, "reading public key")
	// }

	_, _, _, _, err = ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return errors.Wrap(err, "parsing public key")
	}

	c.PublicKey = publicKey

	return nil
}

// GetTokenFromHelper uses the standard vault client binary to retrieve the "current" default token, avoiding reimplementation of token_helper, etc.
func GetTokenFromHelper() (string, error) {
	token, err := exec.Command(clientBinary, "read", "-field=id", "auth/token/lookup-self").Output()
	if err != nil {
		return "", errors.Wrap(err, "getting token from helper")
	}

	return string(token), nil
}

// GetVaultClient returns a full configured Vault API Client
func GetVaultClient() (*api.Client, error) {
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return nil, err
	}

	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	vaultToken := vaultClient.Token()
	if vaultToken == "" {
		vaultToken, err = GetTokenFromHelper()
		if err != nil {
			return nil, err
		}
	}

	vaultClient.SetToken(vaultToken)

	return vaultClient, nil
}

func (c *Client) GetRoleData() map[string]interface{} {
	secret, err := c.API.Logical().Read(fmt.Sprintf("%s/roles/%s", c.Options.Path, c.Options.Role))
	if err != nil || secret == nil {
		return nil
	}

	return secret.Data
}

func (c *Client) GetAllowedUser() string {
	roleData := c.GetRoleData()
	if roleData == nil {
		return ""
	}

	allowedUsersTemplate, ok := roleData["allowed_users_template"].(bool)
	if !ok || allowedUsersTemplate {
		return ""
	}

	allowedUsersString, ok := roleData["allowed_users"].(string)
	if !ok || allowedUsersString == "*" {
		return ""
	}

	allowedUsers := strings.Split(allowedUsersString, ",")
	if len(allowedUsers) != 1 {
		return ""
	}

	return allowedUsers[0]
}

// SignKey signs the configured public key, sets the SignedKey property to the filename of the signed key and returns the filename
func (c *Client) SignKey(principal string) (string, error) {
	request := make(map[string]interface{})

	request["public_key"] = string(c.PublicKey)
	request["valid_principals"] = principal
	request["ttl"] = c.Options.TTL

	if !c.Options.Extensions.Default {
		request["extensions"] = c.RequiredExtensions()
	}

	signedKeySecret, err := c.API.SSHWithMountPoint(c.Options.Path).SignKey(c.Options.Role, request)
	if err != nil {
		return "", err
	}

	c.SignedKey = signedKeySecret.Data["signed_key"].(string)

	return c.SignedKey, nil
}

// GenerateSignedKeypair gets a (private, signed) key-pair
func (c *Client) GenerateSignedKeypair(principal string) (privateKey string, signedKey string, err error) {
	request := make(map[string]interface{})

	request["cert_type"] = "user"
	request["key_type"] = c.Options.Type
	request["key_bits"] = c.Options.Bits
	request["valid_principals"] = principal
	request["ttl"] = c.Options.TTL

	if !c.Options.Extensions.Default {
		request["extensions"] = c.RequiredExtensions()
	}

	secret, err := c.API.Logical().Write(fmt.Sprintf("%s/issue/%s", c.Options.Path, c.Options.Role), request)
	if err != nil {
		return
	}

	privateKey = secret.Data["private_key"].(string)
	signedKey = secret.Data["signed_key"].(string)

	return
}

// RequiredExtensions calculates the required set of extensions to request based on the options set on Client
func (c *Client) RequiredExtensions() map[string]string {
	extensions := map[string]string{}

	if !c.Options.Extensions.NoPTY {
		extensions["permit-pty"] = ""
	}

	if c.Options.Extensions.AgentForwarding {
		extensions["permit-agent-forwarding"] = ""
	}

	if c.Options.Extensions.PortForwarding {
		extensions["permit-port-forwarding"] = ""
	}

	if c.Options.Extensions.UserRC {
		extensions["permit-user-rc"] = ""
	}

	if c.Options.Extensions.X11Forwarding {
		extensions["permit-X11-forwarding"] = ""
	}

	return extensions
}
