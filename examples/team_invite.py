"""Invite a teammate (owner, team-mode server). The account key is sealed for the invitee.

Share ``invitation_id`` and ``redeem_secret`` with the invitee over a secure channel; they
are all that is needed (together with the invitee's own new master password) to join.
See docs/modules/crypto.md (invitation sealing) and docs/security-model.md.
"""

from __future__ import annotations

from dotmage import DotMage

SERVER_URL = "https://secrets.example.com"
MASTER_PASSWORD = "correct horse battery staple"


def main() -> None:
    client = DotMage(SERVER_URL)
    client.unlock(MASTER_PASSWORD)

    with client:
        invite = client.invite("kolya", role="editor", ttl="24h")

    print("Send these to the invitee securely:")
    print("  invitation_id:", invite.invitation_id)
    print("  redeem_secret:", invite.redeem_secret)
    print("  expires_at:   ", invite.expires_at)


if __name__ == "__main__":
    main()
