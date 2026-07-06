# Examples

Runnable snippets for the `dotmage` SDK. Replace the placeholder server URL, secrets, and IDs
with your own. See the [`docs/`](../docs/index.md) for full documentation.

| File | What it shows |
|------|---------------|
| [`quickstart.py`](quickstart.py) | Create a vault, add an app/env, push and pull secrets |
| [`ci_pull.py`](ci_pull.py) | Pull secrets in CI with a scoped token, inject into the environment |
| [`drift_and_diff.py`](drift_and_diff.py) | Detect drift, print a diff, push with conflict handling |
| [`team_invite.py`](team_invite.py) | Invite a teammate (seals the account key for them) |
| [`team_join.py`](team_join.py) | Join a team from an invitation |
| [`rotate.py`](rotate.py) | Offboard a user and rotate the account key |
| [`async_usage.py`](async_usage.py) | The same pull flow with `AsyncDotMage` |

Most examples read configuration from environment variables (prefix `DOTMAGE_`); see
[`.env.example`](../.env.example).
