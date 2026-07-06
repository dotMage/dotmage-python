"""Join a team from an invitation (opens the sealed account key, sets your own password).

See docs/modules/client.md (join) and docs/security-model.md.
"""

from __future__ import annotations

from dotmage import DotMage

SERVER_URL = "https://secrets.example.com"
INVITATION_ID = "paste-invitation-id"
REDEEM_SECRET = "paste-redeem-secret"
MY_MASTER_PASSWORD = "my own strong password"


def main() -> None:
    client, recovery_code = DotMage.join(
        SERVER_URL, INVITATION_ID, REDEEM_SECRET, MY_MASTER_PASSWORD, device_name="kolya-laptop"
    )
    print("Joined. Recovery code (store it safely):", recovery_code)

    with client:
        print("Apps you can see:", [app.name for app in client.list_apps()])


if __name__ == "__main__":
    main()
