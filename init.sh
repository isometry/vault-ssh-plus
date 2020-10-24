export VAULT_ADDR=http://127.0.0.1:8200
vault secrets enable ssh
vault write ssh/config/ca generate_signing_key=true
vault secrets tune -max-lease-ttl=300 ssh
vault write ssh/roles/default - <<-EOH
    {
        "key_type": "ca",
        "allow_user_certificates": true,
        "algorithm_signer": "rsa-sha2-512",
        "allowed_users": "*",
        "default_extensions": [
            {
                "permit-pty": ""
            }
        ],
        "ttl": "300"
    }
EOH
