"""Detect drift, inspect a diff, and push safely with conflict handling.

See docs/modules/client.md and docs/api-reference.md.
"""

from __future__ import annotations

from dotmage import DotMage
from dotmage.exceptions import RevisionConflictError

SERVER_URL = "https://secrets.example.com"
MASTER_PASSWORD = "correct horse battery staple"


def main() -> None:
    client = DotMage(SERVER_URL)
    client.unlock(MASTER_PASSWORD)

    with client:
        drift = client.status("work/api", "prod", local="./.env")
        print("Drift:", drift.state.value)

        if drift.state.value != "synced":
            # Compare the most recent two revisions.
            revisions = client.list_revisions("work/api", "prod")
            if len(revisions) >= 2:
                print(client.diff("work/api", "prod", revisions[-2].rev_number).pretty())

        try:
            result = client.push_from_file("work/api", "prod", "./.env")
            print("Pushed revision", result.rev_number)
        except RevisionConflictError as exc:
            print(f"Remote moved to rev {exc.server_rev}; pull and merge before pushing again.")


if __name__ == "__main__":
    main()
