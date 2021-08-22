package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
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
		return nil, errors.Wrap(err, "parsing arguments")
	}

	if strings.HasPrefix(options.PublicKey, "~/") {
		currentUser, _ := user.Current()
		if err != nil {
			return nil, errors.Wrap(err, "getting current user")
		}

		options.PublicKey = filepath.Join(currentUser.HomeDir, options.PublicKey[2:])
	}

	if err = client.SetPublicKey(options.PublicKey); err != nil {
		return nil, errors.Wrap(err, "setting public key")
	}

	client.API, err = GetVaultClient()
	if err != nil {
		return nil, errors.Wrap(err, "initializing Vault client")
	}

	client.Options = options

	return unparsedArgs, nil
}

func (c *Client) SetPublicKey(fn string) error {
	var err error

	publicKey, err := ioutil.ReadFile(fn)
	if err != nil {
		return errors.Wrap(err, "reading public key")
	}

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

func (c *Client) SignKey(principal string) ([]byte, error) {
	request := make(map[string]interface{})

	request["public_key"] = string(c.PublicKey)
	request["valid_principals"] = principal
	request["ttl"] = c.Options.TTL

	if !c.Options.Extensions.Default {
		request["extensions"] = c.RequiredExtensions()
	}

	signedKeySecret, err := c.API.SSHWithMountPoint(c.Options.Path).SignKey(c.Options.Role, request)
	if err != nil {
		return nil, err
	}
	if signedKeySecret == nil || signedKeySecret.Data == nil {
		return nil, fmt.Errorf("bad data returned from Vault")
	}

	signedKey := []byte(signedKeySecret.Data["signed_key"].(string))

	return signedKey, nil
}

func NewPrivateKey(keyType string) (crypto.Signer, error) {
	var (
		key crypto.Signer
		err error
	)
	switch keyType {
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	case "rsa":
		fallthrough
	default:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func PrivateKeyBytes(key crypto.Signer) ([]byte, error) {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return der, nil
	case *ed25519.PrivateKey:
		return key.Seed(), nil
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(key), nil
	default:
		return nil, nil
	}
}

func (c *Client) NewEphemeralSSHSigner(principal string) (*ssh.Signer, error) {
	// privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	privateKey, err := NewPrivateKey("ed25519")
	if err != nil {
		return nil, errors.Wrap(err, "generating ephemeral private key")
	}

	// XXX
	// privateKeyBytes, _ := PrivateKeyBytes(privateKey)
	// privateKeyBlock := &pem.Block{
	// 	Type:  "PRIVATE KEY",
	// 	Bytes: privateKeyBytes,
	// }

	// privatePEM := pem.EncodeToMemory(privateKeyBlock)
	// log.Println(privatePEM)

	privateSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating ephemeral private signer")
	}

	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "generating ephemeral public key")
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	api, err := GetVaultClient()
	if err != nil {
		return nil, errors.Wrap(err, "getting Vault client")
	}
	client := Client{
		API: api,
		Options: Options{
			Path: "ssh",
			Role: "default",
			TTL:  300,
		},
		PublicKey: publicKeyBytes,
	}
	signedKeyBytes, err := client.SignKey(principal)
	if err != nil {
		return nil, errors.Wrap(err, "signing key")
	}

	signedKey, _, _, _, err := ssh.ParseAuthorizedKey(signedKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing ephemal certificate")
	}

	certificate, ok := signedKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.Wrap(err, "invalid ephemeral certificate")
	}

	certSigner, err := ssh.NewCertSigner(certificate, privateSigner)
	if err != nil {
		return nil, errors.Wrap(err, "creating ephemeral certificate signer")
	}

	return &certSigner, nil
}
