"""Quickstart: create a vault, add an app/environment, push and pull secrets.

Run against a fresh dotMage server. See docs/getting-started.md.
"""

from __future__ import annotations

from dotmage import DotMage

SERVER_URL = "https://secrets.example.com"
BOOTSTRAP_SECRET = "XXXXXXXXXXXX"  # printed by the server on first start
MASTER_PASSWORD = "correct horse battery staple"


def main() -> None:
    # First device on a fresh server: create the vault. Save the recovery code!
    client, recovery_code = DotMage.init_vault(
        SERVER_URL, BOOTSTRAP_SECRET, MASTER_PASSWORD, device_name="laptop"
    )
    print("Recovery code (store it safely, shown once):", recovery_code)

    with client:
        client.create_app("work/api")
        client.create_env("work/api", "prod")

        client.push("work/api", "prod", {"DATABASE_URL": "postgres://u:p@db/app", "DEBUG": "0"})

        secrets = client.pull("work/api", "prod")  # decrypted locally
        print("Pulled keys:", sorted(secrets))


if __name__ == "__main__":
    main()
