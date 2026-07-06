"""The synchronous :class:`DotMage` client — the primary entry point.

Combines the HTTP transport, the endpoint specs, client-side crypto, and an in-memory session
into an ergonomic API. Every method that touches secrets encrypts/decrypts locally; the server
only ever sees ciphertext.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from types import TracebackType
from typing import Any

from dotmage import dotenv
from dotmage.core.api import spec
from dotmage.core.credentials.base import Credentials, CredentialStore
from dotmage.core.credentials.memory import MemoryStore
from dotmage.core.crypto import invitation, keys
from dotmage.core.diffing import compute_diff, compute_drift
from dotmage.core.http.client import Transport
from dotmage.exceptions import ConfigError, NotFoundError
from dotmage.models import (
    AccountKeys,
    App,
    AuditEvent,
    DeviceCredentials,
    DeviceInfo,
    Diff,
    DriftStatus,
    EnrollToken,
    Environment,
    Health,
    InvitePayload,
    InviteResult,
    RedeemResponse,
    RemoveResult,
    Revision,
    RevisionMeta,
    RollbackResult,
    RotateBeginResult,
    RotationStatus,
    Team,
    WhoAmI,
)
from dotmage.session import Session
from dotmage.settings import Settings, get_settings

ProgressCallback = Callable[[int, int], None]


def _as_dict(data: dict[str, str] | str) -> dict[str, str]:
    return dotenv.parse(data) if isinstance(data, str) else dict(data)


class DotMage:
    """Synchronous client for a dotMage server."""

    def __init__(
        self,
        server_url: str | None = None,
        *,
        store: CredentialStore | None = None,
        settings: Settings | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        resolved = server_url or self._settings.SERVER_URL
        if store is None:
            store = MemoryStore(self._seed_credentials(resolved))
        resolved = resolved or store.load().server_url
        if not resolved:
            raise ConfigError(
                "a server URL is required (pass server_url or set DOTMAGE_SERVER_URL)"
            )
        self._store = store
        self._transport = Transport(
            resolved,
            store,
            timeout=timeout if timeout is not None else self._settings.TIMEOUT,
            max_attempts=max_retries if max_retries is not None else self._settings.MAX_RETRIES,
        )
        self.server_url = self._transport.server_url
        self._session = Session()

    # -- construction helpers --------------------------------------------- #

    def _seed_credentials(self, server_url: str | None) -> Credentials:
        creds = Credentials(server_url=server_url)
        if self._settings.DEVICE_TOKEN is not None:
            creds.device_token = self._settings.DEVICE_TOKEN.get_secret_value()
        if self._settings.REFRESH_TOKEN is not None:
            creds.refresh_token = self._settings.REFRESH_TOKEN.get_secret_value()
        return creds

    def _run(self, request: spec.RequestSpec) -> dict[str, Any]:
        return self._transport.request(
            request.method,
            request.path,
            json=request.json,
            params=request.params,
            auth=request.auth,
            headers=request.headers,
        )

    def _save_tokens(self, creds: DeviceCredentials) -> None:
        stored = self._store.load()
        stored.server_url = self.server_url
        stored.device_token = creds.device_token
        stored.refresh_token = creds.refresh_token
        stored.device_id = creds.device_id
        stored.expires_at = creds.expires_at
        self._store.save(stored)

    # -- lifecycle -------------------------------------------------------- #

    @property
    def is_unlocked(self) -> bool:
        return self._session.is_unlocked

    @classmethod
    def init_vault(
        cls,
        server_url: str,
        bootstrap_secret: str,
        master_password: str,
        *,
        with_recovery: bool = True,
        device_name: str = "sdk",
        store: CredentialStore | None = None,
    ) -> tuple[DotMage, str | None]:
        """Create a new vault on a fresh server. Returns the client and a recovery code."""
        client = cls(server_url, store=store)
        creation = keys.create_account_key_material(master_password, with_recovery=with_recovery)
        body = {"bootstrap_secret": bootstrap_secret, "device_name": device_name}
        body.update(asdict(creation.material))
        creds = DeviceCredentials.model_validate(client._run(spec.account_init(body)))
        client._save_tokens(creds)
        client._session.set_key(creation.account_key, key_gen=1)
        return client, creation.recovery_code

    @classmethod
    def enroll(
        cls,
        server_url: str,
        enroll_token: str,
        master_password: str,
        *,
        device_name: str = "sdk",
        store: CredentialStore | None = None,
    ) -> DotMage:
        """Enroll this machine as a new device using an enrollment token, then unlock."""
        client = cls(server_url, store=store)
        creds = DeviceCredentials.model_validate(
            client._run(spec.auth_device(enroll_token, device_name))
        )
        client._save_tokens(creds)
        client.unlock(master_password)
        return client

    @classmethod
    def join(
        cls,
        server_url: str,
        invitation_id: str,
        redeem_secret: str,
        master_password: str,
        *,
        device_name: str = "sdk",
        with_recovery: bool = True,
        store: CredentialStore | None = None,
    ) -> tuple[DotMage, str | None]:
        """Join a team from an invitation. Returns the client and a recovery code."""
        client = cls(server_url, store=store)
        redeemed = RedeemResponse.model_validate(
            client._run(spec.redeem(invitation_id, redeem_secret))
        )
        account_key = invitation.open_account_key(
            redeemed.sealed_ak, redeemed.nonce_inv, redeem_secret
        )
        material, recovery_code = keys.build_key_material(
            account_key,
            master_password,
            with_recovery=with_recovery,
            memory_kib=redeemed.argon_defaults.memory,
            iterations=redeemed.argon_defaults.iterations,
        )
        body: dict[str, Any] = {
            "invitation_id": invitation_id,
            "redeem_secret": redeem_secret,
            "device_name": device_name,
        }
        body.update(asdict(material))
        creds = DeviceCredentials.model_validate(client._run(spec.complete(body)))
        client._save_tokens(creds)
        client._session.set_key(account_key, key_gen=redeemed.key_gen)
        return client, recovery_code

    @classmethod
    def from_ci(
        cls,
        server_url: str,
        ci_token: str,
        master_password: str,
        *,
        store: CredentialStore | None = None,
    ) -> DotMage:
        """Build a client from a scoped CI device token and unlock it."""
        store = store or MemoryStore()
        store.save(Credentials(server_url=server_url, device_token=ci_token))
        client = cls(server_url, store=store)
        client.unlock(master_password)
        return client

    def unlock(self, master_password: str) -> None:
        """Fetch the wrapped account key and unwrap it with the master password."""
        account_keys = AccountKeys.model_validate(self._run(spec.get_keys()))
        account_key = keys.unwrap_account_key(
            master_password,
            salt=account_keys.salt,
            nonce_ak=account_keys.nonce_ak,
            wrapped_ak=account_keys.wrapped_ak,
            argon_memory=account_keys.argon_memory,
            argon_iterations=account_keys.argon_iterations,
        )
        self._session.set_key(account_key, key_gen=account_keys.key_gen)

    def unlock_with_recovery(self, recovery_code: str) -> None:
        """Unwrap the account key using the recovery code instead of the master password."""
        account_keys = AccountKeys.model_validate(self._run(spec.get_keys()))
        account_key = keys.unwrap_account_key_with_recovery(
            recovery_code,
            salt_rc=account_keys.salt_rc,
            nonce_rc=account_keys.nonce_rc,
            wrapped_ak_rc=account_keys.wrapped_ak_rc,
            argon_memory=account_keys.argon_memory,
            argon_iterations=account_keys.argon_iterations,
        )
        self._session.set_key(account_key, key_gen=account_keys.key_gen)

    def lock(self) -> None:
        """Forget the account key held in memory."""
        self._session.clear()

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Re-wrap the account key under a new master password."""
        self.unlock(old_password)
        salt, nonce_ak, wrapped_ak = keys.rewrap_account_key(
            self._session.account_key, new_password
        )
        self._run(spec.patch_keys({"nonce_ak": nonce_ak, "wrapped_ak": wrapped_ak, "salt": salt}))

    # -- server info ------------------------------------------------------ #

    def health(self) -> Health:
        return Health.model_validate(self._run(spec.health()))

    def whoami(self) -> WhoAmI:
        return WhoAmI.model_validate(self._run(spec.whoami()))

    # -- apps & environments --------------------------------------------- #

    def list_apps(self) -> list[App]:
        data = self._run(spec.list_apps())
        return [App.model_validate(item) for item in data.get("apps", [])]

    def create_app(self, name: str) -> App:
        return App.model_validate(self._run(spec.create_app(name)))

    def delete_app(self, name: str) -> None:
        self._run(spec.delete_app(name))

    def list_envs(self, app: str) -> list[Environment]:
        data = self._run(spec.list_envs(app))
        return [Environment.model_validate(item) for item in data.get("environments", [])]

    def create_env(self, app: str, name: str, *, copy_from: str | None = None) -> Environment:
        return Environment.model_validate(self._run(spec.create_env(app, name, copy_from)))

    def delete_env(self, app: str, env: str) -> None:
        self._run(spec.delete_env(app, env))

    def _latest_rev(self, app: str, env: str) -> int:
        for environment in self.list_envs(app):
            if environment.name == env:
                return environment.latest_rev
        raise NotFoundError(f"environment '{env}' not found in app '{app}'")

    # -- secrets ---------------------------------------------------------- #

    def pull(
        self, app: str, env: str, rev: int | str = "last", *, verify: bool = True
    ) -> dict[str, str]:
        """Fetch and decrypt a revision into an env dict."""
        revision = Revision.model_validate(self._run(spec.get_revision(app, env, rev)))
        data = self._session.decrypt(revision.blob)
        if verify:
            from dotmage.core.crypto import blob as _blob

            _blob.verify_content_hash(data, revision.content_hash)
        return data

    def pull_text(self, app: str, env: str, rev: int | str = "last") -> str:
        return dotenv.serialize(self.pull(app, env, rev))

    def pull_to_file(self, app: str, env: str, path: str, rev: int | str = "last") -> None:
        Path(path).write_text(self.pull_text(app, env, rev), encoding="utf-8")

    def push(
        self,
        app: str,
        env: str,
        data: dict[str, str] | str,
        *,
        base_rev: int | None = None,
    ) -> RevisionMeta:
        """Encrypt and push a new revision. Raises RevisionConflictError if the remote moved."""
        payload = _as_dict(data)
        parent_rev = base_rev if base_rev is not None else self._latest_rev(app, env)
        ciphertext, content_hash = self._session.encrypt(payload)
        result = self._run(
            spec.push_revision(
                app, env, blob=ciphertext, content_hash=content_hash, parent_rev=parent_rev
            )
        )
        return RevisionMeta.model_validate(result)

    def push_from_file(self, app: str, env: str, path: str) -> RevisionMeta:
        return self.push(app, env, Path(path).read_text(encoding="utf-8"))

    def set(self, app: str, env: str, updates: dict[str, str]) -> RevisionMeta:
        """Merge ``updates`` into the latest revision and push the result."""
        try:
            current = self.pull(app, env)
        except NotFoundError:
            current = {}
        current.update(updates)
        return self.push(app, env, current)

    # -- revisions -------------------------------------------------------- #

    def list_revisions(self, app: str, env: str) -> list[RevisionMeta]:
        data = self._run(spec.list_revisions(app, env))
        return [RevisionMeta.model_validate(item) for item in data.get("revisions", [])]

    def get_revision(self, app: str, env: str, rev: int | str = "last") -> Revision:
        return Revision.model_validate(self._run(spec.get_revision(app, env, rev)))

    def rollback(self, app: str, env: str, to_rev: int) -> RollbackResult:
        return RollbackResult.model_validate(self._run(spec.rollback(app, env, to_rev)))

    def diff(self, app: str, env: str, a: int | str, b: int | str = "last") -> Diff:
        rev_a = Revision.model_validate(self._run(spec.get_revision(app, env, a)))
        rev_b = Revision.model_validate(self._run(spec.get_revision(app, env, b)))
        return compute_diff(
            app,
            env,
            rev_a.rev_number,
            rev_b.rev_number,
            self._session.decrypt(rev_a.blob),
            self._session.decrypt(rev_b.blob),
        )

    def status(self, app: str, env: str, local: dict[str, str] | str) -> DriftStatus:
        local_dict = _as_dict(local)
        revisions = self.list_revisions(app, env)
        if not revisions:
            return compute_drift(app, env, local_dict, None, 0)
        latest = revisions[-1]
        return compute_drift(app, env, local_dict, latest.content_hash, latest.rev_number)

    # -- devices ---------------------------------------------------------- #

    def list_devices(self) -> list[DeviceInfo]:
        data = self._run(spec.list_devices())
        return [DeviceInfo.model_validate(item) for item in data.get("devices", [])]

    def revoke_device(self, device_id: str) -> None:
        self._run(spec.revoke_device(device_id))

    def gen_enroll_token(self, name: str = "new-device", ttl: str = "1h") -> EnrollToken:
        return EnrollToken.model_validate(self._run(spec.enroll_token(name, ttl)))

    def gen_ci_token(self, app: str, env: str, ttl: str = "30d") -> DeviceCredentials:
        return DeviceCredentials.model_validate(self._run(spec.ci_token(app, env, ttl)))

    # -- team ------------------------------------------------------------- #

    def list_users(self) -> Team:
        return Team.model_validate(self._run(spec.list_users()))

    def invite(self, name: str, role: str = "editor", ttl: str = "24h") -> InvitePayload:
        """Create an invitation, sealing the account key for the invitee."""
        redeem_secret = invitation.generate_redeem_secret()
        nonce_inv, sealed_ak = invitation.seal_account_key(self._session.account_key, redeem_secret)
        body = {
            "name": name,
            "role": role,
            "ttl": ttl,
            "sealed_ak": sealed_ak,
            "nonce_inv": nonce_inv,
            "redeem_hash": invitation.redeem_hash(redeem_secret),
        }
        result = InviteResult.model_validate(self._run(spec.invite(body)))
        return InvitePayload(
            invitation_id=result.invitation_id,
            redeem_secret=redeem_secret,
            name=name,
            role=role,
            expires_at=result.expires_at,
        )

    def change_role(self, user_id: str, role: str) -> None:
        self._run(spec.change_role(user_id, role))

    def remove_user(self, user_id: str) -> RemoveResult:
        return RemoveResult.model_validate(self._run(spec.remove_user(user_id)))

    # -- rotation --------------------------------------------------------- #

    def rotation_status(self) -> RotationStatus:
        return RotationStatus.model_validate(self._run(spec.rotate_status()))

    def rotate(
        self,
        master_password: str,
        *,
        with_recovery: bool = False,
        progress: ProgressCallback | None = None,
    ) -> str | None:
        """Rotate the account key: re-encrypt every revision under a new key, then cut over.

        The session must be unlocked (the old key is needed to read existing blobs). Returns a
        new recovery code when ``with_recovery`` is set.
        """
        account_keys = AccountKeys.model_validate(self._run(spec.get_keys()))
        old_key = self._session.account_key
        status = self.rotation_status()

        if status.in_progress and status.new_key_gen is not None:
            new_gen = status.new_key_gen
            new_key = keys.unwrap_account_key(
                master_password,
                salt=account_keys.salt,
                nonce_ak=status.pending_nonce_ak or account_keys.nonce_ak,
                wrapped_ak=status.pending_wrapped_ak or account_keys.wrapped_ak,
                argon_memory=account_keys.argon_memory,
                argon_iterations=account_keys.argon_iterations,
            )
            recovery_code = None
        else:
            new_gen = status.current_key_gen + 1
            new_key = keys.generate_account_key()
            nonce_ak, wrapped_ak = keys.wrap_with_salt(
                new_key,
                master_password,
                salt=account_keys.salt,
                memory_kib=account_keys.argon_memory,
                iterations=account_keys.argon_iterations,
            )
            begin_body, recovery_code = self._rotation_begin_body(
                new_gen, nonce_ak, wrapped_ak, new_key, master_password, with_recovery
            )
            RotateBeginResult.model_validate(self._run(spec.rotate_begin(begin_body)))

        self._reencrypt_stale(old_key, new_key, new_gen, progress)
        self._run(spec.rotate_complete())
        self._session.set_key(new_key, new_gen)
        return recovery_code

    def _rotation_begin_body(
        self,
        new_gen: int,
        nonce_ak: str,
        wrapped_ak: str,
        new_key: bytes,
        master_password: str,
        with_recovery: bool,
    ) -> tuple[dict[str, Any], str | None]:
        body: dict[str, Any] = {
            "new_key_gen": new_gen,
            "nonce_ak": nonce_ak,
            "wrapped_ak": wrapped_ak,
        }
        recovery_code: str | None = None
        if with_recovery:
            recovery_code = keys.generate_recovery_code()
            salt_rc, nonce_rc, wrapped_ak_rc = keys.rewrap_account_key(
                new_key, keys.normalize_recovery_code(recovery_code)
            )
            body.update(salt_rc=salt_rc, nonce_rc=nonce_rc, wrapped_ak_rc=wrapped_ak_rc)
        return body, recovery_code

    def _reencrypt_stale(
        self,
        old_key: bytes,
        new_key: bytes,
        new_gen: int,
        progress: ProgressCallback | None,
    ) -> None:
        from dotmage.core.crypto import blob as _blob

        done = 0
        while True:
            status = self.rotation_status()
            if not status.stale:
                break
            total = status.stale_count or len(status.stale)
            for stale in status.stale:
                revision = Revision.model_validate(
                    self._run(spec.get_revision(stale.app, stale.env, stale.rev_number))
                )
                data = _blob.decrypt_blob(old_key, revision.blob)
                new_blob, _ = _blob.encrypt_blob(new_key, data)
                self._run(
                    spec.put_blob(
                        stale.app, stale.env, stale.rev_number, blob=new_blob, key_gen=new_gen
                    )
                )
                done += 1
                if progress is not None:
                    progress(done, total)

    # -- audit ------------------------------------------------------------ #

    def audit(
        self, *, app: str | None = None, env: str | None = None, limit: int = 100
    ) -> list[AuditEvent]:
        data = self._run(spec.audit(app, env, limit))
        return [AuditEvent.model_validate(item) for item in data.get("events", [])]

    # -- resource management ---------------------------------------------- #

    def close(self) -> None:
        self._transport.close()
        self._session.clear()

    def __enter__(self) -> DotMage:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
