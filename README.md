# vault-ssh-client (vssh)

A wrapper for the [ssh(1)](https://man.openbsd.org/ssh.1) client to eliminate the overhead of using of short-lived client keys issued from [@hashicorp Vault](https://www.vaultproject.io/).

## Features

* Full support for all [ssh(1)](https://man.openbsd.org/ssh.1) capabilities.
* Automatic and transparent just-in-time delivery of short-lived, signed, single-use [ssh(1)](https://man.openbsd.org/ssh.1) RSA client keys.

## Requirements

* A [HashiCorp Vault](https://www.vaultproject.io/) instance configured for [SSH Client Key Signing](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#client-key-signing), access to an appropriate role, and an SSH server configured to trust the Vault CA.
* An active Vault token (either in the `VAULT_TOKEN` environment variable, or – if the standard `vault` binary is available within `$PATH` – within a Vault Token Helper). The `VAULT_ADDR` environment variable must also be set.
* The `ssh` binary available within `$PATH`.
* A standard SSH private key (stored anywhere supported by ssh(1)), and the associated *unsigned* public key (default: `~/.ssh/id_rsa.pub`).

## Usage

In addition to all the options accepted by [ssh(1)](https://man.openbsd.org/ssh.1), `vssh` accepts the following options:

```console
$ vssh --help
Usage:
  vssh [options] destination [command]

Application Options:
      --version          show version

Vault SSH key signing options:
      --path=            Vault SSH Path (default: ssh) [$VAULT_SSH_PATH]
      --role=            Vault SSH Role (default: default) [$VAULT_SSH_ROLE]
      --ttl=             Vault SSH Certificate TTL (default: 300) [$VAULT_SSH_TTL]
      --port-forwarding  Force permit-port-forwarding extension [$VAULT_SSH_PORT_FORWARDING]
      --pty              Force permit-pty extension [$VAULT_SSH_PTY]
  -P, --public-key=      OpenSSH Public RSA Key to sign (default: ~/.ssh/id_rsa.pub) [$VAULT_SSH_PUBLIC_KEY]

Help Options:
  -h, --help             Show this help message
```

If you need to override the [SSH Client Key Signing](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#client-key-signing) mountpoint or role, this is most easily achieved by setting the `VAULT_SSH_PATH` and `VAULT_SSH_ROLE` environment variables in your shell rc.

Similarly, if you prefer an `ed25519` or `ecdsa` key, override with `VAULT_SSH_PUBLIC_KEY`.

### Example

```console
$ export VAULT_ADDR=https://vault.example.com:8200
$ vault login -method=oidc
...
$ export VAULT_SSH_PATH=ssh-client-signer
$ vssh -N -L8080:localhost:80 host.example.com
...
```

## Installation

### Manual

Download and extract the [latest release](https://github.com/isometry/vault-ssh-client/releases/latest).

### macOS

```sh
brew install isometry/tap/vault-ssh-client
```

### Ansible

If you've already installed my [release-from-github](https://github.com/isometry/ansible-role-release-from-github) role:

```sh
ansible -m import_role -a name=release-from-github -e release_repo=isometry/vault-ssh-client -e release_hashicorp_style=yes localhost
```

## Troubleshooting

Refer to the [Vault Documentation](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#troubleshooting)
