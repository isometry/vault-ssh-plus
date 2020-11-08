#!/bin/bash

set -m

function interrupt_children() {
    [[ -z "$CONTAINER" ]] || docker stop $CONTAINER >/dev/null
    wait
}

trap interrupt_children SIGINT ERR EXIT

env VAULT_ADDR=http://127.0.0.1:8200 vault server -dev -dev-root-token-id=root &
sleep 1

export VAULT_ADDR=http://127.0.0.1:8200

vault secrets enable ssh
vault write ssh/config/ca generate_signing_key=true
vault read -field=public_key ssh/config/ca >trusted-user-ca-keys
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

vault write ssh/roles/root - <<-EOH
    {
        "key_type": "ca",
        "allow_user_certificates": true,
        "algorithm_signer": "rsa-sha2-512",
        "default_user": "root",
        "allowed_users": "root",
        "default_extensions": [],
        "allowed_extensions": "permit-pty,permit-port-forwarding",
        "ttl": "60"
    }
EOH

echo "# Building vault-ssh-target image"
docker image build -t vault-ssh-target .
CONTAINER=$(
    docker container run --detach --rm \
        --publish 2222:22 \
        --volume "$PWD/trusted-user-ca-keys":/etc/ssh/trusted-user-ca-keys \
        vault-ssh-target
)
echo "# STARTED CONTAINER $CONTAINER"
docker container attach --no-stdin --sig-proxy=false $CONTAINER &

fg %1
