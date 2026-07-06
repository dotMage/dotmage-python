"""CI usage: pull secrets with a scoped CI token and inject them into the environment.

The CI token (created via ``gen_ci_token``) authorizes access to one app/env, but decryption
still needs the master password — provide it through your CI secret store. See docs/getting-started.md.

Environment variables expected:
    DOTMAGE_SERVER_URL, DOTMAGE_DEVICE_TOKEN (the CI token), DOTMAGE_MASTER_PASSWORD
"""

from __future__ import annotations

import os

from dotmage import DotMage


def main() -> None:
    client = DotMage.from_ci(
        os.environ["DOTMAGE_SERVER_URL"],
        ci_token=os.environ["DOTMAGE_DEVICE_TOKEN"],
        master_password=os.environ["DOTMAGE_MASTER_PASSWORD"],
    )
    with client:
        secrets = client.pull("work/api", "prod")

    os.environ.update(secrets)
    print(f"Injected {len(secrets)} secrets into the environment.")


if __name__ == "__main__":
    main()
