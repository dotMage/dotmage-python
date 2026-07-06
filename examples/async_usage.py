"""The same pull flow using the asynchronous client.

See docs/modules/async_client.md.
"""

from __future__ import annotations

import asyncio

from dotmage import AsyncDotMage

SERVER_URL = "https://secrets.example.com"
MASTER_PASSWORD = "correct horse battery staple"


async def main() -> None:
    async with AsyncDotMage(SERVER_URL) as client:
        await client.unlock(MASTER_PASSWORD)
        secrets = await client.pull("work/api", "prod")
        print("Pulled keys:", sorted(secrets))


if __name__ == "__main__":
    asyncio.run(main())
