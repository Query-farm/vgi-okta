/**
 * Discovery metadata: the one file to edit when you rename or extend the worker.
 *
 * DuckDB, coding agents and the `vgi-lint` metadata checker all read these
 * tags. Keep every object documented and `make lint-explain` stays at 100.
 *
 * - Catalog-level tags (title, license, author, links, long description) live in
 *   `CATALOG_TAGS` below.
 * - Every function carries `objectTags(...)`: a title, a category from
 *   `SCHEMA_CATEGORIES`, search keywords, and LLM- and human-facing docs.
 */

import { field, type VgiDataType, type VgiField } from "@query-farm/vgi";

export const CATALOG_NAME = "okta";
export const VERSION = "0.1.0";

export const SOURCE_URL = "https://github.com/Query-farm/vgi-okta";

/**
 * Categories group functions in docs and agent tools. Every object's
 * `vgi.category` must name one of these.
 */
export const SCHEMA_CATEGORIES = [
  {
    name: "directory",
    title: "Directory",
    description: "Okta users, groups, memberships, group rules, MFA factors and devices.",
  },
  { name: "apps", title: "Applications", description: "App integrations and their user and group assignments." },
  {
    name: "security",
    title: "Security Configuration",
    description: "Policies and rules, authorization servers, admin role assignments and network zones.",
  },
  {
    name: "audit",
    title: "Audit Events",
    description: "The Okta System Log: sign-ins, MFA, admin and lifecycle events.",
  },
] as const;

export type Category = (typeof SCHEMA_CATEGORIES)[number]["name"];

/** Turn `"a, b, c"` into the JSON array string `vgi.keywords` requires. */
export function keywordsArray(keywords: string): string {
  return JSON.stringify(
    keywords
      .split(",")
      .map((k) => k.trim())
      .filter(Boolean),
  );
}

/** Build the standard per-object discovery tags. */
export function objectTags(opts: {
  title: string;
  category: Category;
  keywords: string;
  docLlm: string;
  docMd: string;
}): Record<string, string> {
  return {
    "vgi.title": opts.title,
    "vgi.category": opts.category,
    "vgi.keywords": keywordsArray(opts.keywords),
    "vgi.doc_llm": opts.docLlm,
    "vgi.doc_md": opts.docMd,
  };
}

/** Build an Arrow field whose `comment` shows up in DuckDB's `DESCRIBE` and agent tools. */
export function column(name: string, type: VgiDataType, comment: string, nullable = true): VgiField {
  return field(name, type, nullable, new Map([["comment", comment]]));
}

const SOURCES_MD =
  "### Sources and references\n\n" +
  "- [Okta Management API](https://developer.okta.com/docs/api/openapi/okta-management/guides/overview/) — the endpoints this worker reads\n" +
  "- [Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/) and [search syntax](https://developer.okta.com/docs/api/#filter)\n" +
  "- [System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/) — since/until/filter/q\n" +
  "- [Pagination](https://developer.okta.com/docs/api/#pagination) and [rate limits](https://developer.okta.com/docs/reference/rl-best-practices/)\n" +
  "- [API tokens](https://help.okta.com/en-us/content/topics/security/api.htm) and [OAuth 2.0 service apps](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)";

export const CATALOG_COMMENT =
  "Okta Workforce Identity as SQL: users, groups, apps, policies, admin roles, devices and the System Log, read-only from the Okta Management API.";

export const CATALOG_DOC_LLM =
  "Read-only SQL access to an Okta Workforce Identity org through the Okta Management API. Reach for it " +
  "to audit who exists and who can do what: user lifecycle and profile attributes, group membership and " +
  "group rules, application assignments (direct or via groups), MFA enrollment, sign-on / password / " +
  "authentication policies, administrator roles, registered devices, network zones, and the System Log " +
  "audit trail of sign-ins and admin changes. Every object needs an `okta` DuckDB secret holding ORG_URL " +
  "plus either an SSWS API_TOKEN or an OAuth 2.0 service app (CLIENT_ID + PRIVATE_KEY, optional KEY_ID " +
  "and SCOPES, private_key_jwt). WHERE filters push down into Okta's own search / filter expressions and " +
  "the System Log since/until window, and are re-checked exactly, so filter early for speed. Per-parent " +
  "collections (group members, app assignments, policy rules, user factors and groups) take the parent " +
  "id as a named argument or a pushed `= / IN` filter, and otherwise fan out over every parent. Column " +
  "names align with the Microsoft Entra workers (user_principal_name, display_name, account_enabled, " +
  "operating_system, created_date_time, app_display_name, ip_address, status) so Okta and Entra rows " +
  "UNION cleanly. Upstream docs: https://developer.okta.com/docs/api/openapi/okta-management/guides/overview/ ; " +
  "System Log https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/ ; " +
  "rate limits https://developer.okta.com/docs/reference/rl-best-practices/ .";

export const CATALOG_DOC_MD =
  "# Okta\n\n" +
  "Query an Okta Workforce Identity org from DuckDB: users, groups and memberships, app assignments, " +
  "MFA factors, policies, admin roles, devices, network zones and the System Log. Read-only.\n\n" +
  "Create an `okta` secret with your org URL (`ORG_URL`) and either an SSWS API token (`API_TOKEN`) or " +
  "an OAuth 2.0 service app (`CLIENT_ID` + `PRIVATE_KEY`). Filters are translated into Okta's " +
  "search/filter syntax and the System Log time window, so only matching rows cross the network; Link " +
  "header paging and Okta's rate-limit headers are handled for you.\n\n" +
  SOURCES_MD;

export const SCHEMA_COMMENT =
  "Read-only Okta Management API collections: directory, applications, security configuration and audit events.";

export const SCHEMA_DOC_LLM =
  "Okta Management API collections as SQL. Org-wide collections are table functions with optional named " +
  "arguments (a raw Okta `search := ` expression, keyword `q := `, `page_size := `) or plain tables when " +
  "they take none. Per-parent collections (memberships, assignments, factors, rules) accept the parent id " +
  "as a named argument or a pushed `= / IN` filter on that id column and otherwise read every parent, one " +
  "extra API call each. The System Log is time-windowed: filter on published to choose the window " +
  "(default lookback 7 days, Okta retains 90). All objects need an `okta` secret.";

export const SCHEMA_DOC_MD =
  "## main\n\n" +
  "Okta Management API collections: the directory, applications and their assignments, security " +
  "configuration and the System Log.\n\n" +
  "Org-wide collections are table functions (or tables when they take no arguments). Per-parent " +
  "collections take the parent id as a named argument or a pushed filter and otherwise read every " +
  "parent.\n\n" +
  "All objects need an `okta` secret; filters push down into Okta's search and filter syntax.";

export const AGENT_TEST_TASKS = [
  { name: "active_engineers", prompt: "List the logins of active users in the Engineering department." },
  { name: "deprovisioned_count", prompt: "How many Okta users are deprovisioned?" },
  { name: "user_lookup", prompt: "When did ada@example.com last sign in to Okta?" },
  { name: "user_memberships", prompt: "Which groups is ada@example.com a member of?" },
  { name: "user_mfa", prompt: "Which MFA factor types has ada@example.com enrolled, and are they active?" },
  { name: "group_count_by_type", prompt: "How many Okta groups are there of each group type?" },
  { name: "engineering_members", prompt: "Who are the members of the Engineering group?" },
  { name: "invalid_rules", prompt: "Are there any group rules that are invalid?" },
  { name: "active_apps", prompt: "List the active Okta applications and their sign-on modes." },
  {
    name: "app_direct_assignments",
    prompt: "Which users are assigned to the Salesforce app directly rather than through a group?",
  },
  { name: "app_group_assignments", prompt: "Which groups are assigned to the Salesforce app?" },
  { name: "password_policies", prompt: "What password policies are configured?" },
  { name: "sign_on_rules", prompt: "List the rules of the default global session (sign-on) policy." },
  { name: "auth_server_issuers", prompt: "What issuer URLs do the custom authorization servers use?" },
  { name: "super_admins", prompt: "Who holds the Super Administrator role?" },
  { name: "devices_by_platform", prompt: "How many registered devices are there per operating system?" },
  { name: "blocklist_zones", prompt: "Which network zones are blocklists?" },
  { name: "failed_signins", prompt: "Which users had failed sign-in attempts in the System Log since 2026-11-10?" },
];

/** Bind-only probes: each binds the function and shows its columns without fetching (LIMIT 0). */
export const EXECUTABLE_EXAMPLES = [
  {
    name: "users_columns",
    description: "The users() result columns (binds only; attach an okta secret and drop LIMIT 0 for rows)",
    sql: "SELECT id, login, status, account_enabled, last_login FROM okta.main.users() LIMIT 0",
  },
  {
    name: "system_log_columns",
    description: "The system_log() result columns (binds only; attach an okta secret and drop LIMIT 0 for rows)",
    sql: "SELECT published, event_type, actor_alternate_id, outcome_result FROM okta.main.system_log() LIMIT 0",
  },
];

export const CATALOG_TAGS: Record<string, string> = {
  "vgi.title": "Okta Workforce Identity",
  "vgi.subtitle": "Okta users, groups, apps, policies, admin roles, devices and System Log events as SQL tables.",
  "vgi.doc_llm": CATALOG_DOC_LLM,
  "vgi.doc_md": CATALOG_DOC_MD,
  "vgi.source_url": SOURCE_URL,
  "vgi.icon_url": "https://query.farm/media-kit/products/vgi/vgi-logo.png",
  "vgi.license": "0BSD",
  "vgi.author": "Query Farm LLC",
  "vgi.copyright": "Copyright 2026 Query Farm LLC - https://query.farm",
  "vgi.keywords": keywordsArray(
    "okta, identity, iam, workforce identity, sso, users, groups, apps, mfa, policies, admin roles, devices, system log, audit, siem",
  ),
  "vgi.support_contact": `${SOURCE_URL}/issues`,
  "vgi.support_policy_url": `${SOURCE_URL}#support`,
  // Public analyst tasks for `vgi-lint simulate`; private graders live in vgi-agent-tests.yaml.
  "vgi.agent_test_tasks": JSON.stringify(AGENT_TEST_TASKS),
  "vgi.executable_examples": JSON.stringify(EXECUTABLE_EXAMPLES),
};

export const SCHEMA_TAGS: Record<string, string> = {
  "vgi.title": "Okta Management API",
  domain: "identity",
  "vgi.keywords": keywordsArray("okta, users, groups, apps, policies, roles, devices, zones, system log"),
  "vgi.doc_llm": SCHEMA_DOC_LLM,
  "vgi.doc_md": SCHEMA_DOC_MD,
  "vgi.categories": JSON.stringify(SCHEMA_CATEGORIES),
};
