package signer

import (
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/jessevdk/go-flags"
)

type Client struct {
	MountPoint *api.SSH
	Options    Options
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
	Default         bool `long:"default-extensions" env:"VAULT_SSH_DEFAULT_EXTENSIONS" description:"Disable Principal of Least Privilege and request signer-default extensions"`
	AgentForwarding bool `long:"agent-forwarding" env:"VAULT_SSH_AGENT_FORWARDING" description:"Force permit-agent-forwarding extension"`
	PortForwarding  bool `long:"port-forwarding" env:"VAULT_SSH_PORT_FORWARDING" description:"Force permit-port-forwarding extension"`
	NoPTY           bool `long:"no-pty" env:"VAULT_SSH_NO_PTY" description:"Force disable permit-pty extension"`
	UserRC          bool `long:"user-rc" env:"VAULT_SSH_USER_RC" description:"Force permit-user-rc extension"`
	X11Forwarding   bool `long:"x11-forwarding" env:"VAULT_SSH_X11_FORWARDING" description:"Force permit-X11-forwarding extension"`
}

func ParseArgs(args []string) (Client, []string, error) {
	var options Options

	parser := flags.NewParser(&options, flags.HelpFlag|flags.PassDoubleDash|flags.IgnoreUnknown)
	unparsedArgs, err := parser.ParseArgs(args)
	if err != nil {
		return Client{}, nil, err
	}

	currentUser, _ := user.Current()
	if err != nil {
		return Client{}, nil, err
	}
	homeDir := currentUser.HomeDir

	if strings.HasPrefix(options.PublicKey, "~/") {
		options.PublicKey = filepath.Join(homeDir, options.PublicKey[2:])
	}

	if _, err := os.Stat(options.PublicKey); os.IsNotExist(err) {
		return Client{}, nil, err
	}

	// TODO: further validate public key

	// VaultClient instance is not fully initialised!
	vault := Client{
		Options: options,
	}

	return vault, unparsedArgs, nil
}

// GetTokenFromHelper uses the standard vault client binary to retrieve the "current" default token, avoiding reimplementation of token_helper, etc.
func GetTokenFromHelper() (string, error) {
	token, err := exec.Command(clientBinary, "read", "-field=id", "auth/token/lookup-self").Output()
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// SetMountPoint sets the MountPoint attribute to the appropriate Vault API SSH MountPoint
func (c *Client) SetMountPoint() error {
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return err
	}

	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		return err
	}

	vaultToken := vaultClient.Token()
	if vaultToken == "" {
		vaultToken, err = GetTokenFromHelper()
		if err != nil {
			return err
		}
	}

	vaultClient.SetToken(vaultToken)

	c.MountPoint = vaultClient.SSHWithMountPoint(c.Options.Path)

	return nil
}

// GetSignedKey signs the configured public key, sets the SignedKey property to the filename of the signed key and returns the filename
func (c *Client) GetSignedKey(principal string) (string, error) {
	publicKeyBytes, err := ioutil.ReadFile(c.Options.PublicKey)
	if err != nil {
		return "", err
	}

	request := make(map[string]interface{})

	request["public_key"] = string(publicKeyBytes)
	request["valid_principals"] = principal
	request["ttl"] = c.Options.TTL

	if !c.Options.Extensions.Default {
		request["extensions"] = c.RequiredExtensions()
	}

	if err := c.SetMountPoint(); err != nil {
		return "", err
	}

	signedKeySecret, err := c.MountPoint.SignKey(c.Options.Role, request)
	if err != nil {
		return "", err
	}

	signedKey := signedKeySecret.Data["signed_key"].(string)

	return signedKey, nil
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
