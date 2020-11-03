# vault-ssh-plus (vssh)

An enhanced implementation of [`vault ssh`](https://www.vaultproject.io/docs/commands/ssh), wrapping the OpenSSH `ssh` client to eliminate the management overhead of using of short-lived SSH client keys CA-signed by [@hashicorp Vault](https://www.vaultproject.io/).

## Features

* Support for all [`ssh(1)`](https://man.openbsd.org/ssh.1) capabilities, including:
  * non-filesystem private keys (e.g. `gpg-agent`, PKCS#11, etc.);
  * arbitrary [`ssh_config(5)`](https://man.openbsd.org/ssh_config.5) configuration (e.g. `Host` aliases and `Match` clauses);
  * `ControlMaster` connection sharing.
* Automatic and transparent just-in-time delivery of short-lived, CA-signed, single-use `ssh` client keys.
* Adherence to the Principal of Least Privilege: by default, signed keys only permit the specific extensions required for the `ssh` options given.
* Automatic username mapping for Vault roles with a single, fixed entry in `allowed_users` (e.g. `root`, `jenkins`, `ansible`).
* Significantly lower memory overhead than `vault ssh`.

## Requirements

* A [HashiCorp Vault](https://www.vaultproject.io/) instance configured for [SSH Client Key Signing](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#client-key-signing), access to an appropriate role, and an SSH server configured to trust the Vault CA.
* An active Vault token (either in the `VAULT_TOKEN` environment variable, or – if the standard `vault` binary is available within `$PATH` – available from a Vault Token Helper). The `VAULT_ADDR` environment variable must also be set.
* OpenSSH 7.2 or newer `ssh` client binary.
* A standard SSH private key (stored anywhere supported by `ssh`), and the associated *unsigned* public key (default: `~/.ssh/id_rsa.pub`). `vssh` does *not* require access to the private key.

## Usage

In addition to all the options accepted by [`ssh(1)`](https://man.openbsd.org/ssh.1), `vssh` accepts the following options:

```console
$ vssh --help
Usage:
  vssh [options] destination [command]

Application Options:
      --version                           Show version

Vault SSH key signing Options:
      --path=                             Vault SSH Path (default: ssh) [$VAULT_SSH_PATH]
      --role=                             Vault SSH Role (default: default) [$VAULT_SSH_ROLE]
      --ttl=                              Vault SSH Certificate TTL (default: 300) [$VAULT_SSH_TTL]
  -P, --public-key=                       OpenSSH Public RSA Key to sign (default: ~/.ssh/id_rsa.pub) [$VAULT_SSH_PUBLIC_KEY]

Certificate Extensions:
      --default-extensions                Disable automatic extension calculation and request signer-default extensions [$VAULT_SSH_DEFAULT_EXTENSIONS]
      --agent-forwarding                  Force permit-agent-forwarding extension [$VAULT_SSH_AGENT_FORWARDING]
      --port-forwarding                   Force permit-port-forwarding extension [$VAULT_SSH_PORT_FORWARDING]
      --no-pty                            Force disable permit-pty extension [$VAULT_SSH_NO_PTY]
      --user-rc                           Enable permit-user-rc extension [$VAULT_SSH_USER_RC]
      --x11-forwarding                    Force permit-X11-forwarding extension [$VAULT_SSH_X11_FORWARDING]

Help Options:
  -h, --help                              Show this help message
```

If you need to override the [SSH Client Key Signing](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#client-key-signing) mountpoint or role, this is most easily achieved by setting the `VAULT_SSH_PATH` and `VAULT_SSH_ROLE` environment variables in your shell rc.

Similarly, if you prefer an `ed25519` or `ecdsa` key, override with `VAULT_SSH_PUBLIC_KEY`.

By default, the certificate will be requested with only those extensions required for the current command (default `permit-pty` unless `-N` is specified). Additional extensions may be requested (e.g. to support expected future multiplexed connections) with the "Certificate Extensions" arguments, or the Vault role default extensions may be forced with `--default-extensions`.

### Example

The following will request that the ed25519 public key be signed by the Vault signed at `https://vault.example.com:8200/v1/ssh/sign/ssh-client-signer`, with `permit-pty` and `permit-port-forwarding` extensions to support the connection to `host.example.com`

```console
$ export VAULT_ADDR=https://vault.example.com:8200 VAULT_SSH_PATH=ssh-client-signer VAULT_SSH_PUBLIC_KEY=~/.ssh/id_ed25519.pub
$ vault login -method=oidc
...
$ vssh -L8080:localhost:80 host.example.com
...
```

## Installation

### Manual

Download and extract the [latest release](https://github.com/isometry/vault-ssh-plus/releases/latest).

### macOS

```sh
brew install isometry/tap/vault-ssh-plus
```

### Ansible

If you've already installed my [release-from-github](https://github.com/isometry/ansible-role-release-from-github) role:

```sh
ansible -m import_role -a name=release-from-github -e release_repo=isometry/vault-ssh-plus -e release_hashicorp_style=yes localhost
```

## Troubleshooting

Refer to the [Vault Documentation](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#troubleshooting)
