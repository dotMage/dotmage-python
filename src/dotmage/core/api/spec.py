"""Request specifications for every dotMage endpoint.

Each function returns a :class:`RequestSpec`; it performs no I/O. App names may contain
slashes (folders) and are placed into the path verbatim — the server matches them with a
``{name:path}`` parameter, so they must not be URL-encoded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from dotmage.enums import MethodEnum

V1 = "/api/v1"


@dataclass(frozen=True)
class RequestSpec:
    """A fully-described HTTP request, ready to be executed by a transport."""

    method: MethodEnum
    path: str
    json: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    auth: bool = True
    headers: dict[str, str] | None = field(default=None)


def _env(name: str) -> str:
    """URL-encode an environment segment (env names are plain path segments server-side)."""
    return quote(name, safe="")


# --- Health & account ----------------------------------------------------- #


def health() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, "/health", auth=False)


def account_init(body: dict[str, Any]) -> RequestSpec:
    return RequestSpec(MethodEnum.POST, f"{V1}/account/init", json=body, auth=False)


def get_keys() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/account/keys")


def patch_keys(body: dict[str, Any]) -> RequestSpec:
    return RequestSpec(MethodEnum.PATCH, f"{V1}/account/keys", json=body)


# --- Auth ----------------------------------------------------------------- #


def auth_device(enroll_token: str, device_name: str) -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/auth/device",
        json={"device_name": device_name},
        auth=False,
        headers={"Authorization": f"Bearer {enroll_token}"},
    )


def device_register_bootstrap(bootstrap_secret: str, device_name: str) -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/auth/device-register",
        json={"bootstrap_secret": bootstrap_secret, "device_name": device_name},
        auth=False,
    )


# --- Apps & environments -------------------------------------------------- #


def list_apps() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/apps")


def create_app(name: str) -> RequestSpec:
    return RequestSpec(MethodEnum.POST, f"{V1}/apps", json={"name": name})


def delete_app(name: str) -> RequestSpec:
    return RequestSpec(MethodEnum.DELETE, f"{V1}/apps/{name}")


def list_envs(app: str) -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/apps/{app}/envs")


def create_env(app: str, name: str, copy_from: str | None = None) -> RequestSpec:
    body: dict[str, Any] = {"name": name}
    if copy_from is not None:
        body["copy_from"] = copy_from
    return RequestSpec(MethodEnum.POST, f"{V1}/apps/{app}/envs", json=body)


def delete_env(app: str, env: str) -> RequestSpec:
    return RequestSpec(MethodEnum.DELETE, f"{V1}/apps/{app}/envs/{_env(env)}")


# --- Revisions ------------------------------------------------------------ #


def push_revision(
    app: str, env: str, *, blob: str, content_hash: str | None, parent_rev: int
) -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/apps/{app}/envs/{_env(env)}/revisions",
        json={"blob": blob, "content_hash": content_hash, "parent_rev": parent_rev},
    )


def get_revision(app: str, env: str, rev: int | str) -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/apps/{app}/envs/{_env(env)}/revisions/{rev}")


def list_revisions(app: str, env: str) -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/apps/{app}/envs/{_env(env)}/revisions")


def rollback(app: str, env: str, to_rev: int) -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/apps/{app}/envs/{_env(env)}/rollback",
        json={"to_rev": to_rev},
    )


# --- Devices -------------------------------------------------------------- #


def list_devices() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/devices")


def revoke_device(device_id: str) -> RequestSpec:
    return RequestSpec(MethodEnum.DELETE, f"{V1}/devices/{device_id}")


def enroll_token(name: str, ttl: str, kind: str = "enrollment") -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/devices/enroll-token",
        json={"name": name, "ttl": ttl, "kind": kind},
    )


def ci_token(app: str, env: str, ttl: str) -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/devices/ci-token",
        json={"app": app, "env": env, "ttl": ttl},
    )


# --- Team ----------------------------------------------------------------- #


def whoami() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/whoami")


def list_users() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/users")


def invite(body: dict[str, Any]) -> RequestSpec:
    return RequestSpec(MethodEnum.POST, f"{V1}/users/invite", json=body)


def redeem(invitation_id: str, redeem_secret: str) -> RequestSpec:
    return RequestSpec(
        MethodEnum.POST,
        f"{V1}/invitations/redeem",
        json={"invitation_id": invitation_id, "redeem_secret": redeem_secret},
        auth=False,
    )


def complete(body: dict[str, Any]) -> RequestSpec:
    return RequestSpec(MethodEnum.POST, f"{V1}/invitations/complete", json=body, auth=False)


def change_role(user_id: str, role: str) -> RequestSpec:
    return RequestSpec(MethodEnum.PATCH, f"{V1}/users/{user_id}", json={"role": role})


def remove_user(user_id: str) -> RequestSpec:
    return RequestSpec(MethodEnum.DELETE, f"{V1}/users/{user_id}")


# --- Rotation ------------------------------------------------------------- #


def rotate_begin(body: dict[str, Any]) -> RequestSpec:
    return RequestSpec(MethodEnum.POST, f"{V1}/account/rotate/begin", json=body)


def rotate_status() -> RequestSpec:
    return RequestSpec(MethodEnum.GET, f"{V1}/account/rotate")


def rotate_complete() -> RequestSpec:
    return RequestSpec(MethodEnum.POST, f"{V1}/account/rotate/complete")


def put_blob(app: str, env: str, rev: int, *, blob: str, key_gen: int) -> RequestSpec:
    return RequestSpec(
        MethodEnum.PUT,
        f"{V1}/apps/{app}/envs/{_env(env)}/revisions/{rev}/blob",
        json={"blob": blob, "key_gen": key_gen},
    )


# --- Audit ---------------------------------------------------------------- #


def audit(app: str | None = None, env: str | None = None, limit: int = 100) -> RequestSpec:
    params: dict[str, Any] = {"limit": limit}
    if app is not None:
        params["app"] = app
    if env is not None:
        params["env"] = env
    return RequestSpec(MethodEnum.GET, f"{V1}/audit", params=params)
