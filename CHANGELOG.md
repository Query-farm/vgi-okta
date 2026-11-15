# Changelog

## 0.1.0 (unreleased)

First release: read-only Okta Management API access from DuckDB.

- Table functions: users, user, user_groups, user_factors, groups, group_members,
  group_rules, apps, app_users, app_groups, policy_rules, authorization_servers,
  admin_role_assignments, devices, system_log. Tables: policies, network_zones.
- `okta` secret: ORG_URL plus an SSWS API_TOKEN, or an OAuth 2.0 service app
  (CLIENT_ID + PRIVATE_KEY, private_key_jwt with RS256/ES256).
- Pushdown into Okta search/filter expressions and the System Log since/until window
  (clamped to the 90-day retention). Per-parent collections fan out or narrow on the
  parent id.
- Link-header paging with the cursor in serializable scan state. X-Rate-Limit-aware backoff.
- Entra-aligned column names for UNIONs with the vgi-azure-* workers.

Targets: @query-farm/vgi 0.50 · VGI protocol 3.3 · Haybarn 2.0.0rc11 · vgi-lint-check 2.x (unpinned)
