<p align="center">
  <img src="https://query.farm/media-kit/products/vgi/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A Query.Farm VGI worker for DuckDB.</em></p>

# Query Okta Users, Groups, Apps, Policies and the System Log in DuckDB

> **vgi-okta** · a [Query.Farm](https://query.farm) VGI worker · written in TypeScript

[![CI](https://github.com/Query-farm/vgi-okta/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-okta/actions/workflows/ci.yml)
[![vgi worker: query.farm](https://query.farm/media-kit/shields/vgi-worker.svg)](https://query.farm)

Okta Workforce Identity as SQL, read-only, through the
[Okta Management API](https://developer.okta.com/docs/api/openapi/okta-management/guides/overview/):
who exists, which groups and apps they have, how they sign in, who administers the org,
and what happened in the System Log.

```sql
CREATE SECRET okta (TYPE okta, ORG_URL 'https://acme.okta.com', API_TOKEN '00a…');

-- Active engineers who have not signed in for 90 days (one Okta search request).
SELECT login, display_name, last_login
FROM okta.main.users()
WHERE status = 'ACTIVE' AND department = 'Engineering'
  AND (last_login IS NULL OR last_login < now() - INTERVAL 90 DAY);

-- Failed sign-ins in the last day, by user (since/until + filter pushed to /api/v1/logs).
SELECT actor_alternate_id, count(*) AS failures
FROM okta.main.system_log()
WHERE published > now() - INTERVAL 1 DAY
  AND event_type = 'user.session.start' AND outcome_result = 'FAILURE'
GROUP BY ALL ORDER BY failures DESC;
```

## Functions and tables

All live in `okta.main`. Per-parent collections take the parent id as a named argument
(`group_id := '00g…'`) **or** a pushed `WHERE group_id = … / IN (…)` filter; with neither
they list every parent and read each in turn (one extra API call per parent).

| Object | Okta endpoint | What pushes down |
|---|---|---|
| `users(search := NULL, page_size := 200)` | `GET /api/v1/users` | `status`, `account_enabled = true`, `id`, `login`/`user_principal_name`, `email`, `first_name`, `last_name`, `department`, `title` (`=`, `IN`, `starts_with`/`LIKE 'x%'`), `employee_number`, `manager_id`, `user_type_id`, `created`/`last_updated`/`status_changed` ranges → SCIM `search`; `search :=` adds a raw expression |
| `user(id_or_login)` | `GET /api/v1/users/{id}` | — (zero rows when not found) |
| `user_groups(user_id := NULL)` | `GET /api/v1/users/{id}/groups` | `user_id` |
| `user_factors(user_id := NULL)` | `GET /api/v1/users/{id}/factors` | `user_id` (types and status only; factor profiles are never returned) |
| `groups(search := NULL, page_size := 200)` | `GET /api/v1/groups` | `id`, `display_name` (`=`, `IN`, prefix), `group_type`, timestamp ranges → `search` |
| `group_members(group_id := NULL, page_size := 1000)` | `GET /api/v1/groups/{id}/users` | `group_id` |
| `group_rules(search := NULL)` | `GET /api/v1/groups/rules` | — |
| `apps(q := NULL, page_size := 200)` | `GET /api/v1/apps` | `status`, `name` (single `=`) → `filter` (credentials and settings are never returned) |
| `app_users(app_id := NULL, page_size := 500)` | `GET /api/v1/apps/{id}/users` | `app_id` |
| `app_groups(app_id := NULL)` | `GET /api/v1/apps/{id}/groups` | `app_id` |
| `policies` (table) | `GET /api/v1/policies?type=…` | `type` (`=`/`IN`: only those types are requested), `status` |
| `policy_rules(policy_id := NULL)` | `GET /api/v1/policies/{id}/rules` | `policy_id` |
| `authorization_servers(q := NULL)` | `GET /api/v1/authorizationServers` | — |
| `admin_role_assignments(user_id := NULL, group_id := NULL)` | `GET /api/v1/iam/assignees/users` + `/users/{id}/roles`, `/groups/{id}/roles` | — |
| `devices(search := NULL, page_size := 200)` | `GET /api/v1/devices?expand=user` | `id`, `status`, `account_enabled = true`, `operating_system`, `display_name` (prefix), timestamp ranges → `search` |
| `network_zones` (table) | `GET /api/v1/zones` | `usage` or `id` (single `=`) → `filter` |
| `system_log(q, filter_expr, lookback_days := 7, sort_order := 'ASCENDING', page_size := 1000)` | `GET /api/v1/logs` | `published`/`created_date_time` ranges → `since`/`until`; `event_type` (`=`, `IN`, prefix), `actor_id`, `actor_alternate_id`, `actor_type`, `outcome_result`/`status`, `severity`, `ip_address`, `transaction_id`, `uuid` → `filter` |

Pushdown only narrows the request. The SDK re-applies every pushed predicate to each
batch (`autoApplyFilters`), so results are exact even where Okta matches more loosely
(profile matching is case-insensitive in Okta, for instance). Anything not listed is
filtered by DuckDB.

**System Log window.** Every request is bounded: `until` defaults to the moment the scan
started, `since` to `lookback_days` before it. Okta keeps 90 days and rejects an older
`since`, so a lower bound older than that is clamped to the retention window. Bounding
the request also avoids Okta's polling mode, where an ascending query without `until`
always returns a next link.

**Okta behaviour worth knowing.** An unfiltered `users()` omits `DEPROVISIONED` users, as
Okta's list does; filter `status = 'DEPROVISIONED'` (or use `search :=`) to see them.
`admin_role_assignments()` with no arguments lists users who hold a role. A group's roles
come from `group_id :=`.

### Columns that line up with Microsoft Entra

Where the concept is the same, columns use the names from the `vgi-azure-*` workers, so
Okta and Entra rows UNION directly. On users: `user_principal_name` (Okta login),
`display_name` and `account_enabled` (status = ACTIVE). On groups: `display_name`. On
devices: `display_name`, `operating_system` and `account_enabled`. On the System Log:
`id`, `created_date_time`, `user_principal_name` (a user actor's login),
`app_display_name` (the first AppInstance target), `ip_address` and `status` (outcome).
Native Okta names (`login`, `published`, `outcome_result`, …) are present too.

```sql
SELECT 'okta' AS idp, user_principal_name, display_name, account_enabled FROM okta.main.users()
UNION ALL
SELECT 'entra', user_principal_name, display_name, account_enabled
FROM azure.main.directory_users_delta() WHERE _row_kind IS NULL;
```

Types are real: timestamps are `TIMESTAMPTZ`, priorities `INTEGER`, flags `BOOLEAN`,
id lists `VARCHAR[]`, System Log targets `STRUCT(id, type, alternate_id, display_name)[]`.
Open shapes (profiles with custom attributes, policy conditions/actions, debug data) are
`JSON`.

## Authentication

Create one `okta` secret. `ORG_URL` is required (`https://` only, except
`http://127.0.0.1`/`localhost` for local test servers), then either:

- **API token (SSWS):** `API_TOKEN '…'` from *Security → API → Tokens*. Requests carry
  `Authorization: SSWS <token>` and run with that admin's permissions.
- **OAuth 2.0 service app** (`private_key_jwt`): `CLIENT_ID '0oa…'`, `PRIVATE_KEY '<PEM or JWK>'`
  (RSA → RS256, EC P-256 → ES256; `\n` escapes in a one-line PEM are accepted), optional
  `KEY_ID` (the `kid`), and optional `SCOPES` (defaults to the `okta.*.read` scopes every
  object needs: users, groups, apps, logs, policies, authorizationServers, roles,
  devices, networkZones). The worker signs a client assertion with `node:crypto`,
  exchanges it at `<org>/oauth2/v1/token`, and caches the access token in memory until
  shortly before it expires. DPoP-bound tokens are not supported; turn off *Require DPoP*
  on the service app.

```sql
CREATE SECRET okta (TYPE okta, ORG_URL 'https://acme.okta.com',
                    CLIENT_ID '0oa…', KEY_ID 'kid-1', PRIVATE_KEY '-----BEGIN PRIVATE KEY-----\n…');
```

`API_TOKEN` and `PRIVATE_KEY` are redacted secret fields. Credentials are read from the
secret on every call and never stored in scan state, so they never travel in HTTP
continuation tokens. Pagination links are followed only on the org's own origin.

## Paging and rate limits

Each Okta page becomes one Arrow batch. The cursor (the `rel="next"` Link URL, plus the
pending parent ids during a fan-out) lives in the table function's serializable state,
so long scans resume on any worker process over the HTTP transport. Every response's
`X-Rate-Limit-Remaining`/`-Reset` is tracked: a 429 waits until the reset (up to 65 s),
the worker pauses on its own when a bucket is about to run dry, and 5xx and network
errors retry with exponential backoff.

## Install

**Prerequisites:** [Bun](https://bun.sh) 1.3+ (for a source checkout).

```bash
git clone https://github.com/Query-farm/vgi-okta.git && cd vgi-okta
bun install --frozen-lockfile
```

**DuckDB 2.0:**

```sql
SET allow_extension_repositories = 'allowed';
CREATE EXTENSION REPOSITORY IF NOT EXISTS query_farm WITH PREFIX 'https://duckdb-extensions.query.farm';
INSTALL vgi FROM query_farm;
LOAD vgi FROM query_farm;
ATTACH 'okta' (TYPE vgi, LOCATION '/abs/path/to/vgi-okta/bin/vgi-okta-worker');
```

**Haybarn 2.0.1+** (`uvx haybarn-cli`; Haybarn 2.0.0 serves an older vgi extension that cannot attach this worker):

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'okta' (TYPE vgi, LOCATION '/abs/path/to/vgi-okta/bin/vgi-okta-worker');
```

`LOCATION` is the command DuckDB runs, so use an absolute path. Tagged releases ship
signed standalone executables (no Bun needed) for Linux, macOS (arm64) and Windows; point
`LOCATION` at the downloaded binary. The same binary serves HTTP with `--http --port 8000`
(see the `Dockerfile`).

## Testing

```bash
make test-unit                 # bun unit tests (pushdown translation, JWT signing, paging, backoff)
make test-sql                  # test/sql/okta.test through Haybarn 2.0 (stdio)
make test-sql TRANSPORT=http   # …over HTTP (also: launch)
make check                     # everything CI runs
```

No test touches the network or a real Okta org. `test/mock_api/server.py` is a
stdlib-only replay server over a hand-built org (`test/fixtures/okta-org.json`, shaped
after Okta's documented responses). It checks the `SSWS` token, or verifies the
ES256/RS256 client assertion and enforces scopes for service-app tokens. It rejects
unknown query parameters and evaluates `search`/`filter` expressions, so pushdown really
narrows the data. It pages with `after` cursors and Link headers, enforces the System
Log retention window, and answers a 429 and a 503 once each so the retry paths always
run. The SQL tests read its `/__requests` log to check exactly what was pushed down.
The service-app keys in `test/fixtures` are test-only keys generated for these fixtures.

The metadata check runs with `execute: false` in CI: every object needs an `okta` secret
for a live org.

## Authorship & License

Written by [Query.Farm](https://query.farm). Released under the
[BSD Zero Clause License](LICENSE) (0BSD).

Copyright 2026 Query Farm LLC - https://query.farm
