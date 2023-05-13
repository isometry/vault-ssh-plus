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

## Usage

In addition to all the options accepted by [`ssh(1)`](https://man.openbsd.org/ssh.1), `vssh` accepts the following options:

```console
$ vssh --help
Usage:
  vssh [options] destination [command]

Application Options:
      --mode=[sign|issue]                   Mode (default: issue) [$VAULT_SSH_MODE]
      --type=[rsa|ec|ed25519]               Preferred key type (default: ed25519) [$VAULT_SSH_KEY_TYPE]
      --bits=[0|2048|3072|4096|256|384|521] Key bits for 'issue' mode (default: 0) [$VAULT_SSH_KEY_BITS]
      --path=                               Vault SSH mountpoint (default: ssh) [$VAULT_SSH_PATH]
      --role=                               Vault SSH role (default: <ssh-username>) [$VAULT_SSH_ROLE]
      --ttl=                                Vault SSH certificate TTL (default: 300) [$VAULT_SSH_TTL]
  -P, --public-key=                         Path to preferred public key for 'sign' mode [$VAULT_SSH_PUBLIC_KEY]
      --version                             Show version

Certificate Extensions:
      --default-extensions                  Disable automatic extension calculation and request signer-default extensions [$VAULT_SSH_DEFAULT_EXTENSIONS]
      --agent-forwarding                    Force permit-agent-forwarding extension [$VAULT_SSH_AGENT_FORWARDING]
      --port-forwarding                     Force permit-port-forwarding extension [$VAULT_SSH_PORT_FORWARDING]
      --no-pty                              Force disable permit-pty extension [$VAULT_SSH_NO_PTY]
      --user-rc                             Enable permit-user-rc extension [$VAULT_SSH_USER_RC]
      --x11-forwarding                      Force permit-X11-forwarding extension [$VAULT_SSH_X11_FORWARDING]

Help Options:
  -h, --help                                Show this help message
```

If you need to override the [SSH Client Key Signing](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#client-key-signing) mountpoint or role, this is most easily achieved by setting the `VAULT_SSH_PATH` and `VAULT_SSH_ROLE` environment variables in your shell rc.
If your Vault SSH mountpoint isn't configured with a role matching the target SSH username, you *will* need to specify the Vault SSH role to use (e.g. `export VAULT_SSH_ROLE=self` or `vssh --role=self host` if you're using a role named `self` configured with templated `allowed_users`).

In `issue` mode (the default), the client will retrieve an ephemeral keypair from Vault, exposed to `ssh(1)` via an internal SSH agent.

In `sign` mode, the client will sign the public key specified, defaulting to the first key added into `ssh-agent(1)` (preferring the first of type matching `VAULT_SSH_KEY_TYPE`).

The certificate will be requested with only those extensions required for the current command (default `permit-pty` unless `-N` is specified). Additional extensions may be requested (e.g. to support expected future multiplexed connections) with the "Certificate Extensions" arguments, or the Vault role default extensions may be forced with `--default-extensions`.

### Examples

The following will request that an existing ed25519 public key be signed by the Vault signer at `https://vault.example.com:8200/v1/ssh-client-signer/sign/default`, with (automatic) `permit-pty` and `permit-port-forwarding` extensions to support the connection to `host.example.com`:

```console
$ ssh-add ~/.ssh/id_ed25519
$ export VAULT_ADDR=https://vault.example.com:8200
$ export VAULT_SSH_PATH=ssh-client-signer
$ export VAULT_SSH_ROLE=default
$ export VAULT_SSH_MODE=sign
$ vault login
...
$ vssh -L8080:localhost:80 host.example.com
...
```

The following will request that an ephemeral ecdsa keypair with a (default) 256-bit private key be generated by the Vault issuer at `https://vault.example.com/v1/ssh/issue/root`, and used to run the `id` command on `host2.example.com` as `root`:

```console
$ export VAULT_ADDR=https://vault.example.com
$ export VAULT_SSH_KEY_TYPE=ec
$ vault login
...
$ vssh root@host2.example.com id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
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

### Arch Linux

vault-ssh-plus has been added to the AUR repository, and can be found at `https://aur.archlinux.org/packages/vault-ssh-plus-bin`. 
Either install via makepkg, or your favourite AUR helper.

## Troubleshooting

Refer to the [Vault Documentation](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html#troubleshooting)
