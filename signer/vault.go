package signer

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/jessevdk/go-flags"
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
	Path       string     `long:"path" default:"ssh" env:"VAULT_SSH_PATH" description:"Vault SSH Path"`
	Role       string     `long:"role" default:"default" env:"VAULT_SSH_ROLE" description:"Vault SSH Role"`
	TTL        uint       `long:"ttl" default:"300" env:"VAULT_SSH_TTL" description:"Vault SSH Certificate TTL"`
	PublicKey  string     `short:"P" long:"public-key" default:"~/.ssh/id_rsa.pub" env:"VAULT_SSH_PUBLIC_KEY" description:"OpenSSH Public RSA Key to sign"`
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

func ParseArgs(client *Client, args []string) ([]string, error) {
	var options Options

	parser := flags.NewParser(&options, flags.PassDoubleDash|flags.IgnoreUnknown)
	unparsedArgs, err := parser.ParseArgs(args)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(options.PublicKey, "~/") {
		currentUser, _ := user.Current()
		if err != nil {
			return nil, err
		}

		options.PublicKey = filepath.Join(currentUser.HomeDir, options.PublicKey[2:])
	}

	if err = client.SetPublicKey(options.PublicKey); err != nil {
		return nil, err
	}

	client.API, err = GetVaultClient()
	if err != nil {
		return nil, err
	}

	client.Options = options

	return unparsedArgs, nil
}

func (c *Client) SetPublicKey(fn string) error {
	var err error

	publicKey, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}

	_, _, _, _, err = ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return err
	}

	c.PublicKey = publicKey

	return nil
}

// GetTokenFromHelper uses the standard vault client binary to retrieve the "current" default token, avoiding reimplementation of token_helper, etc.
func GetTokenFromHelper() (string, error) {
	token, err := exec.Command(clientBinary, "read", "-field=id", "auth/token/lookup-self").Output()
	if err != nil {
		return "", err
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

// GetSignedKey signs the configured public key, sets the SignedKey property to the filename of the signed key and returns the filename
func (c *Client) GetSignedKey(principal string) (string, error) {
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
