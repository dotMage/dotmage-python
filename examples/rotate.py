"""Offboard a user and rotate the account key (owner only).

Removing a user drops their key wraps, but the account key itself is unchanged until you
rotate — so rotate afterwards to make the old key useless. See docs/api-reference.md (rotation).
"""

from __future__ import annotations

from dotmage import DotMage

SERVER_URL = "https://secrets.example.com"
MASTER_PASSWORD = "correct horse battery staple"
USER_TO_REMOVE = "paste-user-id"


def main() -> None:
    client = DotMage(SERVER_URL)
    client.unlock(MASTER_PASSWORD)

    with client:
        result = client.remove_user(USER_TO_REMOVE)
        print(f"Removed {result.name}; revoked {result.devices_revoked} device(s).")

        if result.rotation_required:
            client.rotate(
                MASTER_PASSWORD,
                progress=lambda done, total: print(f"re-encrypted {done}/{total}"),
            )
            print("Rotation complete.")


if __name__ == "__main__":
    main()
