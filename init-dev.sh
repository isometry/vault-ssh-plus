#!/bin/bash

set -m

vault server -dev -dev-root-token-id=root &
sleep 5

export VAULT_ADDR=http://127.0.0.1:8200

vault secrets enable ssh
vault write ssh/config/ca generate_signing_key=true
vault read -field=public_key ssh-client-signer/config/ca >trusted-user-ca-keys
vault secrets tune -max-lease-ttl=300 ssh

vault write ssh/roles/default - <<-EOH
    {
        "key_type": "ca",
        "allow_user_certificates": true,
        "algorithm_signer": "rsa-sha2-512",
        "allowed_users": "*",
        "default_extensions": [],
        "allowed_extensions": "permit-pty,permit-port-forwarding,permit-X11-forwarding",
        "ttl": "300"
    }
EOH

fg
