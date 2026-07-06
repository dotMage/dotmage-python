# План: Python SDK `dotmage`

> Клиентская библиотека для self-hosted E2E-шифрованного менеджера секретов **dotMage**.
> Публикуется в публичный PyPI. Стиль и tooling наследуются от внутреннего референса
> `posthogsdk` (`E:\code\dotmage\posthog-connector-master`). Backend — `E:\code\server`.

## 0. Главный принцип

Сервер dotMage — **zero-knowledge blob store**: хранит только непрозрачный зашифрованный
`blob` и обёрнутые ключи, **никогда** не видит мастер-пароль, plaintext-секреты и account
key (AK). Поэтому SDK состоит из двух равновеликих частей:

1. **Транспорт** — типизированный клиент над REST `/api/v1` (httpx + tenacity +
   pydantic-settings + loguru).
2. **Клиентская криптография** — то, что делает эталонный CLI `dmage`: деривация ключей,
   обёртка/распаковка AK, шифрование/дешифрование blob, sealed-AK для приглашений, ротация.

## 1. Крипто-модель (контракт, воспроизводимый SDK)

```
master_password ──Argon2id(salt, mem=65536KiB, iter=3, par=1, ver=19)──► KEK (32B)
                                                                            │ unwrap
account key AK (32B, случайный, общий на аккаунт/команду) ◄──────── wrapped_ak/nonce_ak
   │ encrypt
   ▼
blob = base64( version || nonce(24) || AEAD(AK, nonce)(canonical_json({KEY:VALUE})) )
content_hash = sha256(canonical_plaintext)  # только для дрейфа/diff, сервер не валидирует
```

- KDF: **libsodium `crypto_pwhash(ALG_ARGON2ID13)`** через PyNaCl (`argon_version=19` +
  `parallelism=1` — это его сигнатура). `memlimit = argon_memory*1024`, `opslimit = argon_iterations`.
- Wrap AK: `SecretBox(KEK).encrypt(AK)` (XSalsa20-Poly1305, nonce 24B).
- Recovery-путь: `salt_rc/nonce_rc/wrapped_ak_rc` — тот же AK под KEK из recovery-кода.
- Приглашения: `nonce_inv/sealed_ak = SecretBox(key_from(redeem_secret)).encrypt(AK)`,
  `redeem_hash = sha256(redeem_secret)`.
- Ротация: новый AK → перешифровать каждую stale-ревизию → cutover; `key_gen` на ревизии.

> ⚠️ **Interop-риск.** Точные примитивы (secretbox vs xchacha, длина соли, единицы memlimit,
> кодировка base64, envelope blob, `key_from(redeem_secret)`) должны **побайтово** совпасть с
> `dmage`/`dotmage-spec`. Всё вынесено в `crypto/suite.py` (единственный источник констант);
> перед релизом — этап interop-сверки по тест-векторам. Реализуется описанный libsodium-профиль.

## 2. Стек и tooling

| Категория | Выбор |
|---|---|
| Python | `>=3.10,<4.0`, target `py310` |
| Менеджер / сборка | Poetry, PEP 621 `[project]`, `poetry-core` |
| HTTP | httpx (sync `Client` + async `AsyncClient`) |
| Retry | tenacity (экспон. джиттер, 5 попыток, retryable статусы+исключения) |
| Конфиг | pydantic-settings, prefix `DOTMAGE_`, `SecretStr`, `@lru_cache get_settings()` |
| Логи | loguru |
| Крипта | **PyNaCl** (libsodium) |
| .env I/O | собственный мини-парсер (без внешних зависимостей) |
| Линт/формат/типы | Ruff (`E,W,F,I,UP,B,C4,SIM,TID,RUF`, line-length 100) + mypy strict |
| Тесты | pytest + pytest-cov + pytest-asyncio + respx (мок httpx) |
| Типизация | `py.typed` (PEP 561) |
| Публикация | GitHub Actions → **публичный PyPI** (OIDC trusted publishing) |

**Поверхность API:** sync-first `DotMage` (основной) + зеркальный `AsyncDotMage`, общий низкоуровневый слой.

## 3. Фичи (маппинг на эндпоинты)

- **Discovery/lifecycle:** `health`, `init_vault`, `enroll`, `unlock`/`unlock_with_recovery`/`lock`, `change_master_password`.
- **Apps/envs:** `list_apps`, `create_app`, `delete_app`, `list_envs`, `create_env(copy_from)`, `delete_env`.
- **Секреты (ядро):** `pull`/`pull_text`/`pull_to_file`, `push`/`push_from_file`/`set`, `exec`.
- **Ревизии:** `list_revisions`, `get_revision`, `diff` (клиентский), `rollback`, `status` (дрейф).
- **Устройства:** `list_devices`, `revoke_device`, `gen_enroll_token`, `gen_ci_token`, `from_ci`.
- **Команда (team):** `whoami`, `list_users`, `invite`, `join`, `change_role`, `remove_user`.
- **Ротация (owner):** `rotate` (оркестратор), `rotation_status`.
- **Аудит:** `audit(app, env, limit)`.

Полный справочник эндпоинтов, схем запросов/ответов и кодов ошибок — в разделе 6 (см. также
исходный backend `E:\code\server`). Ключевые нюансы:
- Поля токенов: `token_expires_at` (init/auth/refresh/complete) vs `expires_at` (ci/enroll/invite).
- `RotationNotActiveError` = HTTP **405**; остальные ротационные ошибки = 409.
- push: `parent_rev` обязателен и == `latest_rev`; 409 `RevisionConflictError` → pull→merge→retry.
- `{name:path}`: слэши в имени app не URL-энкодить; solo → team-ручки дают 404 `TeamModeRequiredError`.

## 4. Файловая структура

```
dotmage-python/
├── pyproject.toml, poetry.lock, README.md, CHANGELOG.md, LICENSE, PLAN.md, .gitignore
├── scripts/linters.sh                 # ruff check --fix + ruff format --check + mypy + pytest --cov
├── .pre-commit-config.yaml
├── .github/workflows/ci.yml           # check-version / lint / test(+coverage gate) / build / publish
├── docs/                              # подробная документация по каждому модулю
│   ├── index.md, getting-started.md, crypto.md, security-model.md, api-reference.md
│   └── modules/{client,async_client,session,crypto,http,credentials,models,exceptions,settings}.md
├── src/dotmage/
│   ├── __init__.py (публичный реэкспорт), py.typed, settings.py, client.py, async_client.py
│   ├── session.py, models.py, exceptions.py, enums.py, dotenv.py
│   └── core/
│       ├── http/{client.py, retry.py}
│       ├── api/{account,auth,apps,revisions,devices,users,rotation,audit,health}.py
│       ├── credentials/{base,memory,file}.py
│       └── crypto/{suite,kdf,aead,keys,blob,invitation}.py
├── tests/            # см. раздел 5 — максимальное покрытие
└── examples/         # см. раздел 7
```

## 5. Тестирование — МАКСИМАЛЬНОЕ покрытие, проверяемое в пайплайне

Цель: высокое покрытие, **жёстко проверяемое в CI** (сборка падает при недоборе).

- Фреймворк: **pytest** + **pytest-cov** (`--cov=dotmage --cov-branch`), **pytest-asyncio**
  (async-клиент), **respx** (мок httpx-запросов без реального сервера).
- **Порог покрытия в CI:** `--cov-fail-under=95` (строки + ветви). Стадия `test` пайплайна
  падает, если ниже. Отчёт `term-missing` + `xml` (для артефакта/бейджа).
- Наборы тестов:
  - `test_crypto_roundtrip.py` — KDF детерминизм, wrap/unwrap AK, blob enc/dec, recovery-путь,
    seal/open приглашения, порча тега → `DecryptionError`.
  - `test_crypto_vectors.py` — **interop-векторы** (замороженные пары master_password/salt/…
    → ожидаемые байты) для защиты от регрессий формата; помечены как контракт с `dmage`.
  - `test_blob.py` — каноничная сериализация .env-словаря (порядок, экранирование, юникод),
    `content_hash` стабилен.
  - `test_dotenv.py` — парсер/сериализатор .env (комментарии, кавычки, пустые, `export`).
  - `test_http_retry.py` — retryable статусы/исключения, число попыток, backoff, `reraise`.
  - `test_http_client.py` — инъекция Bearer, авто-refresh на 401, ротация токенов.
  - `test_error_mapping.py` — каждый `error.code` сервера → правильный класс SDK (по таблице).
  - `test_models.py` — валидация pydantic-моделей запросов/ответов, различия полей токенов.
  - `test_credentials.py` — Memory/File стор, права `0600`, persist/rotate.
  - `test_client_flows.py` / `test_async_client_flows.py` — init/unlock/push/pull/diff/rollback/
    status/devices/team/rotation/audit end-to-end на respx-моках, включая ветки ошибок
    (RevisionConflict, RotationInProgress, TeamModeRequired, scope).
  - `test_session.py` — lock/unlock, стирание AK, выбор `key_gen`.
- Тесты исключены из mypy (`exclude = ["tests/"]`), но проходят ruff.
- Локальный прогон — тем же `scripts/linters.sh`, что и в CI и pre-commit (единый источник).

## 6. Обработка ошибок

Иерархия `DotMageError` (`status_code`, `code`, `message`). Транспорт мапит `error.code`
из тела `{"error":{"code","message"}}` в типизированные исключения: `AuthenticationError`,
`TokenExpiredError` (триггер refresh), `BootstrapError`, `AccountStateError`,
`RevisionConflictError(server_rev, parent_rev)`, `NotFoundError`, `RotationError`,
`PermissionError`, `TeamModeRequiredError`, `TeamError`, `RateLimitError`; плюс клиентские
`DecryptionError`, `MasterPasswordError`, `ContentIntegrityError`, `InteropError`.

## 7. Документация — подробно по каждому модулю, с референсами

- `docs/` в Markdown; каждый модуль SDK описан отдельной страницей в `docs/modules/`:
  назначение, публичные символы, сигнатуры, примеры, **референсы** на соответствующие
  эндпоинты/поля backend (`server/src/...`) и на строки крипто-контракта (`crypto/suite.py`).
- `docs/security-model.md` — угрозы, что видит/не видит сервер, роль мастер-пароля, recovery,
  ротация; `docs/crypto.md` — точная спецификация примитивов и envelope (источник для interop).
- `docs/api-reference.md` — таблица всех методов `DotMage`/`AsyncDotMage` с маппингом на HTTP.
- Google-style docstrings во всём коде; README — quickstart + ссылки на `docs/`.

## 8. Примеры — папка `examples/`

- `quickstart.py` — init_vault → create_app/env → push/pull.
- `ci_pull.py` — scoped CI-токен + мастер-пароль из env, инъекция секретов в процесс.
- `drift_and_diff.py` — status/diff/безопасный push с обработкой конфликта.
- `team_invite.py` / `team_join.py` — приглашение и вступление (sealed AK).
- `rotate.py` — ротация ключа после оффбординга.
- `async_usage.py` — тот же сценарий на `AsyncDotMage`.
- Каждый пример — самодостаточный, с комментариями и ссылкой на соответствующую страницу docs.

## 9. Версионность (ключевое правило)

- Semver в `pyproject.toml`, старт `0.1.0`; изменения копятся в `CHANGELOG.md` под `[Unreleased]`
  (формат Keep a Changelog), на релизе секция датируется и версия бампается.
- CI-стадия **`check-version`**: запрашивает PyPI JSON API; если текущая версия уже
  опубликована — пайплайн **падает** с требованием бампнуть версию (порт паттерна из референса
  `version-already-published`). Публикация (`build`+`publish`) — только с ветки `master/main`.
- Пре-релизные ветки/PR: стадии `lint` + `test` обязательны; версия должна оставаться валидной
  и уникальной на всех прогонах пайплайна.

## 10. План работ (коммиты, все от лица пользователя, без AI-атрибуции)

1. Каркас: pyproject/ruff/mypy/pytest, CI, pre-commit, `linters.sh`, README/CHANGELOG/LICENSE,
   `.gitignore`, пакет + `py.typed`.
2. Крипто-ядро (`suite/kdf/aead/keys/blob/invitation`) + `dotenv` + тесты round-trip/vectors.
3. `settings`, `enums`, `exceptions`, `models` + тесты.
4. Транспорт (`http/client`, `http/retry`) + `credentials` + тесты.
5. Низкоуровневый `core/api/*`.
6. `session` + `DotMage` (sync) + тесты флоу.
7. `AsyncDotMage` + async-тесты.
8. `docs/` по модулям + `examples/`.
9. Финализация CI (порог покрытия, check-version), README, CHANGELOG.
