/**
 * The Okta table functions: one spec per Management API endpoint.
 *
 * Column names follow Okta's own fields in snake_case, plus Entra-aligned names
 * (`user_principal_name`, `display_name`, `account_enabled`, `operating_system`,
 * `created_date_time`, `app_display_name`, `ip_address`, `status`) where the concept
 * matches the vgi-azure-* workers, so Okta and Microsoft Entra rows can be UNIONed.
 */

import { int64, utf8, type VgiFunction } from "@query-farm/vgi";
import type { OktaConfig } from "./client.ts";
import { type AttrMap, andJoin, buildExpression, type Constraint, eqValues, oktaTime, timeBounds } from "./pushdown.ts";
import { asStr, C, type Col, defineOktaCatalogTable, defineOktaTable, getAll, type Row } from "./table.ts";

const Q = "okta.main";
const PAGE_SIZE_DOC = "Rows requested per Okta page (named; the endpoint's maximum is used when larger).";

/** Clamp a page_size argument to an endpoint's maximum. */
const pageSize = (v: unknown, max: number) => String(Math.min(Number(v ?? max), max));

/** Keep only single-value equality constraints (for endpoints whose `filter` has no `or`). */
const eqOnly = (cs: Constraint[]) => cs.filter((c) => c.kind === "cmp" && c.op === "eq");

const enc = encodeURIComponent;

// ------------------------------------------------------------------------ users

const displayName = (p: Row | undefined): string | null => {
  if (!p) return null;
  if (typeof p.displayName === "string" && p.displayName) return p.displayName;
  const n = [p.firstName, p.lastName].filter((x) => typeof x === "string" && x).join(" ");
  return n || null;
};

/** User columns shared by users / user / group_members. */
function userColumns(): Col[] {
  return [
    C.str("id", "Okta user id (00u…).", "id", false),
    C.str(
      "status",
      "Lifecycle status: STAGED, PROVISIONED, ACTIVE, RECOVERY, PASSWORD_EXPIRED, LOCKED_OUT, SUSPENDED or DEPROVISIONED.",
      "status",
    ),
    C.bool("account_enabled", "Entra-aligned: true when status is ACTIVE (the user can sign in normally).", (r) =>
      typeof r.status === "string" ? r.status === "ACTIVE" : null,
    ),
    C.str("login", "The user's Okta login (profile.login), usually an email address.", "profile.login"),
    C.str("user_principal_name", "Entra-aligned alias of login (Okta's sign-in name).", "profile.login"),
    C.str("email", "Primary email (profile.email).", "profile.email"),
    C.str("display_name", "profile.displayName, else first + last name.", (r) => displayName(r.profile)),
    C.str("first_name", "profile.firstName.", "profile.firstName"),
    C.str("last_name", "profile.lastName.", "profile.lastName"),
    C.str("department", "profile.department.", "profile.department"),
    C.str("title", "Job title (profile.title).", "profile.title"),
    C.str("employee_number", "profile.employeeNumber.", "profile.employeeNumber"),
    C.str("manager_id", "profile.managerId.", "profile.managerId"),
    C.str("user_type_id", "Okta user type id (type.id).", "type.id"),
    C.str(
      "credential_provider",
      "Credential provider type: OKTA, ACTIVE_DIRECTORY, LDAP, FEDERATION, SOCIAL or IMPORT.",
      "credentials.provider.type",
    ),
    C.time("created", "When the user was created.", "created"),
    C.time("activated", "When the user was activated.", "activated"),
    C.time("status_changed", "When status last changed.", "statusChanged"),
    C.time("last_login", "Last successful sign-in.", "lastLogin"),
    C.time("last_updated", "When the user object last changed.", "lastUpdated"),
    C.time("password_changed", "When the password last changed.", "passwordChanged"),
    C.json("profile", "The full user profile, including custom attributes, as JSON.", "profile"),
  ];
}

const USER_ATTRS: Record<string, AttrMap> = {
  id: { attr: "id", kind: "string" },
  status: { attr: "status", kind: "string" },
  account_enabled: { attr: "status", kind: "bool", value: (v) => (v === true ? "ACTIVE" : undefined) },
  login: { attr: "profile.login", kind: "string", prefix: true },
  user_principal_name: { attr: "profile.login", kind: "string", prefix: true },
  email: { attr: "profile.email", kind: "string", prefix: true },
  first_name: { attr: "profile.firstName", kind: "string", prefix: true },
  last_name: { attr: "profile.lastName", kind: "string", prefix: true },
  department: { attr: "profile.department", kind: "string", prefix: true },
  title: { attr: "profile.title", kind: "string", prefix: true },
  employee_number: { attr: "profile.employeeNumber", kind: "string" },
  manager_id: { attr: "profile.managerId", kind: "string" },
  user_type_id: { attr: "type.id", kind: "string" },
  created: { attr: "created", kind: "time", range: true },
  last_updated: { attr: "lastUpdated", kind: "time", range: true },
  status_changed: { attr: "statusChanged", kind: "time", range: true },
};

export const users = defineOktaTable<{ search: string | null; page_size: bigint }>({
  name: "users",
  description: "Okta users, with SQL filters pushed into Okta's search expression",
  title: "Okta Users",
  category: "directory",
  keywords: "okta, users, people, accounts, identity, directory, workforce, login, scim search",
  docLlm:
    "Every Okta user (GET /api/v1/users) as one row each: id, status, account_enabled, login / " +
    "user_principal_name, email, display_name, names, department, title, manager_id, timestamps " +
    "(created, activated, last_login, last_updated, password_changed) and the full profile as JSON. " +
    "WHERE filters on status, account_enabled = true, id, login, email, first/last name, department, " +
    "title, employee_number, manager_id, user_type_id (eq / IN / starts_with) and created / last_updated / " +
    "status_changed ranges become Okta's SCIM `search` expression; `search := '...'` adds a raw expression " +
    "(e.g. custom profile attributes). DEPROVISIONED users are returned only when filtered for explicitly " +
    "or searched for, as Okta does.",
  docMd: "## users(search := NULL, page_size := 200)\n\nOkta users, one row each, paged with the `Link` header.",
  pushdown:
    "`status`, `account_enabled = true`, `id`, `login`/`user_principal_name`, `email`, `first_name`, `last_name`, " +
    "`department`, `title` (eq, IN, starts_with), `employee_number`, `manager_id`, `user_type_id` (eq, IN), " +
    "`created`/`last_updated`/`status_changed` (ranges) → `search`.",
  args: { search: utf8(), page_size: int64() },
  argDefaults: { search: null, page_size: 200 },
  argDocs: {
    search: "Optional raw Okta search expression ANDed with the pushed filters, e.g. 'profile.costCenter eq \"42\"'.",
    page_size: PAGE_SIZE_DOC,
  },
  argConstraints: { page_size: { ge: 1, le: 1000 } },
  columns: userColumns(),
  requests: ({ args, constraints }) => [
    {
      path: "/api/v1/users",
      query: {
        search: andJoin(buildExpression(constraints, USER_ATTRS), args.search),
        limit: pageSize(args.page_size, 200),
      },
    },
  ],
  examples: [
    {
      sql: `SELECT login, display_name, department FROM ${Q}.users() WHERE status = 'ACTIVE' AND department = 'Engineering' ORDER BY login`,
      description: "Active engineers (both predicates become one Okta search)",
    },
    {
      sql: `SELECT status, count(*) AS users FROM ${Q}.users() GROUP BY status ORDER BY users DESC`,
      description: "User count by lifecycle status",
    },
  ],
});

export const getUser = defineOktaTable<{ id_or_login: string }>({
  name: "user",
  description: "One Okta user by id or login",
  title: "Okta User Lookup",
  category: "directory",
  keywords: "okta, user, lookup, by id, by login, profile",
  docLlm:
    "Look up a single Okta user by id (00u…) or login (GET /api/v1/users/{id}). Returns the same columns " +
    "as users(), or zero rows if the user does not exist.",
  docMd: "## user(id_or_login)\n\nOne Okta user by id or login; zero rows when not found.",
  args: { id_or_login: utf8() },
  argDocs: { id_or_login: "The user's Okta id (00u…) or login (e.g. 'ada@example.com')." },
  columns: userColumns(),
  notFoundEmpty: true,
  requests: ({ args }) => (args.id_or_login ? [{ path: `/api/v1/users/${enc(args.id_or_login)}` }] : []),
  examples: [
    {
      sql: `SELECT id, status, last_login FROM ${Q}.user('ada@example.com')`,
      description: "Status and last sign-in of one user",
    },
  ],
});

// ----------------------------------------------------------------------- groups

function groupColumns(): Col[] {
  return [
    C.str("id", "Okta group id (00g…).", "id", false),
    C.str("display_name", "Group name (profile.name); Entra-aligned column name.", "profile.name"),
    C.str("description", "profile.description.", "profile.description"),
    C.str("group_type", "OKTA_GROUP (Okta-mastered), APP_GROUP (imported from an app/directory) or BUILT_IN.", "type"),
    C.strList(
      "object_class",
      "The group's objectClass list, e.g. okta:user_group or okta:windows_security_principal.",
      "objectClass",
    ),
    C.time("created", "When the group was created.", "created"),
    C.time("last_updated", "When the group's profile last changed.", "lastUpdated"),
    C.time("last_membership_updated", "When membership last changed.", "lastMembershipUpdated"),
    C.json("profile", "The full group profile as JSON (AD-sourced groups carry extra attributes).", "profile"),
  ];
}

const GROUP_ATTRS: Record<string, AttrMap> = {
  id: { attr: "id", kind: "string" },
  display_name: { attr: "profile.name", kind: "string", prefix: true },
  group_type: { attr: "type", kind: "string" },
  created: { attr: "created", kind: "time", range: true },
  last_updated: { attr: "lastUpdated", kind: "time", range: true },
  last_membership_updated: { attr: "lastMembershipUpdated", kind: "time", range: true },
};

export const groups = defineOktaTable<{ search: string | null; page_size: bigint }>({
  name: "groups",
  description: "Okta groups, with SQL filters pushed into Okta's search expression",
  title: "Okta Groups",
  category: "directory",
  keywords: "okta, groups, security groups, directory groups, app groups, membership",
  docLlm:
    "Every Okta group (GET /api/v1/groups): id, display_name, description, group_type (OKTA_GROUP / " +
    "APP_GROUP / BUILT_IN), object_class, created / last_updated / last_membership_updated and the profile " +
    "JSON. Filters on id, display_name (eq / IN / starts_with), group_type and the timestamps push into " +
    "Okta's `search`; `search := '...'` adds a raw expression. Join to group_members(id) for members.",
  docMd: "## groups(search := NULL, page_size := 200)\n\nOkta groups, one row each.",
  pushdown: "`id`, `display_name` (eq, IN, starts_with), `group_type`, and timestamp ranges → `search`.",
  args: { search: utf8(), page_size: int64() },
  argDefaults: { search: null, page_size: 200 },
  argDocs: {
    search: "Optional raw Okta group search expression ANDed with the pushed filters.",
    page_size: PAGE_SIZE_DOC,
  },
  argConstraints: { page_size: { ge: 1, le: 10000 } },
  columns: groupColumns(),
  requests: ({ args, constraints }) => [
    {
      path: "/api/v1/groups",
      query: {
        search: andJoin(buildExpression(constraints, GROUP_ATTRS), args.search),
        limit: pageSize(args.page_size, 10000),
      },
    },
  ],
  examples: [
    {
      sql: `SELECT display_name, last_membership_updated FROM ${Q}.groups() WHERE group_type = 'OKTA_GROUP' ORDER BY display_name`,
      description: "Okta-mastered groups and when their membership last changed",
    },
    {
      sql: `SELECT group_type, count(*) FROM ${Q}.groups() GROUP BY group_type ORDER BY group_type`,
      description: "Groups by type",
    },
  ],
});

/** Parent listings for org-wide fan-out. */
const ALL_USERS = [{ path: "/api/v1/users", query: { limit: "200" } }];
const ALL_GROUPS = [{ path: "/api/v1/groups", query: { limit: "1000" } }];
const ALL_APPS = [{ path: "/api/v1/apps", query: { limit: "200" } }];
const idOf = (r: Row) => asStr(r.id);
const FANOUT_NOTE =
  "With no id, every parent is listed and read in turn (one extra call per parent — filter on the id " +
  "column or pass the named argument to target specific ones).";

export const userGroups = defineOktaTable<{ user_id: string | null }>({
  name: "user_groups",
  description: "Group memberships of Okta users",
  title: "Okta User Group Memberships",
  category: "directory",
  keywords: "okta, user groups, membership, member of, groups for user",
  docLlm:
    "The groups each user is a member of (GET /api/v1/users/{id}/groups): user_id plus the same columns as " +
    "groups(). Pass user_id := '<id or login>' or filter WHERE user_id = '…' / IN (…) to read specific users; " +
    "without either every user (except DEPROVISIONED) is read. " +
    FANOUT_NOTE,
  docMd: "## user_groups(user_id := NULL)\n\nGroups the user(s) belong to.",
  pushdown: "`user_id` (eq / IN) selects which users are read.",
  args: { user_id: utf8() },
  argDefaults: { user_id: null },
  argDocs: { user_id: "Only this user (Okta id or login); NULL reads every user." },
  columns: [C.ctx("user_id", "The user id (or the login that was passed in).", "user_id"), ...groupColumns()],
  notFoundEmpty: true,
  fanout: {
    key: "user_id",
    parents: ALL_USERS,
    parentId: idOf,
    child: (id) => ({ path: `/api/v1/users/${enc(id)}/groups`, ctx: { user_id: id } }),
  },
  examples: [
    {
      sql: `SELECT display_name FROM ${Q}.user_groups(user_id := 'ada@example.com') ORDER BY display_name`,
      description: "Group names for one user",
    },
    {
      sql: `SELECT u.login, count(*) AS groups FROM ${Q}.user_groups() g JOIN ${Q}.users() u ON u.id = g.user_id GROUP BY ALL ORDER BY groups DESC`,
      description: "Users by number of group memberships",
    },
  ],
});

export const groupMembers = defineOktaTable<{ group_id: string | null; page_size: bigint }>({
  name: "group_members",
  description: "Members of Okta groups",
  title: "Okta Group Members",
  category: "directory",
  keywords: "okta, group members, membership, users in group",
  docLlm:
    "Group membership (GET /api/v1/groups/{id}/users): group_id, user_id, plus the user columns (status, " +
    "login, email, display_name, account_enabled, …). Pass group_id := '00g…' or filter WHERE group_id = '…' " +
    "/ IN (…); without either every group's members are read. " +
    FANOUT_NOTE,
  docMd: "## group_members(group_id := NULL, page_size := 1000)\n\nUsers who are members of groups.",
  pushdown: "`group_id` (eq / IN) selects which groups are read.",
  args: { group_id: utf8(), page_size: int64() },
  argDefaults: { group_id: null, page_size: 1000 },
  argDocs: { group_id: "Only this group (00g…); NULL reads every group.", page_size: PAGE_SIZE_DOC },
  argConstraints: { page_size: { ge: 1, le: 1000 } },
  columns: [
    C.ctx("group_id", "The group id.", "group_id"),
    ...userColumns().map((c) => (c.name === "id" ? { ...c, name: "user_id", doc: "Member's Okta user id." } : c)),
  ],
  notFoundEmpty: true,
  fanout: {
    key: "group_id",
    parents: ALL_GROUPS,
    parentId: idOf,
    child: (id, { args }) => ({
      path: `/api/v1/groups/${enc(id)}/users`,
      query: { limit: pageSize(args.page_size, 1000) },
      ctx: { group_id: id },
    }),
  },
  examples: [
    {
      sql: `SELECT login, status FROM ${Q}.group_members() WHERE group_id = '00g2eng' AND account_enabled ORDER BY login`,
      description: "Active members of one group (group_id pushes down)",
    },
    {
      sql: `SELECT g.display_name, count(*) AS members FROM ${Q}.group_members() m JOIN ${Q}.groups() g ON g.id = m.group_id GROUP BY ALL ORDER BY members DESC`,
      description: "Member count per group",
    },
  ],
});

export const userFactors = defineOktaTable<{ user_id: string | null }>({
  name: "user_factors",
  description: "Enrolled MFA factors of Okta users (type and status only)",
  title: "Okta User MFA Factors",
  category: "directory",
  keywords: "okta, mfa, factors, authenticators, push, totp, webauthn, enrollment",
  docLlm:
    "The MFA factors users have enrolled (GET /api/v1/users/{id}/factors): user_id, factor_id, factor_type " +
    "(push, token:software:totp, webauthn, sms, …), provider, vendor_name, status and timestamps. Factor " +
    "profiles (phone numbers, device keys) are deliberately not returned. Pass user_id := or filter on " +
    "user_id; without either every user is read. " +
    FANOUT_NOTE,
  docMd: "## user_factors(user_id := NULL)\n\nMFA factor enrollments — types and status only, no factor profiles.",
  pushdown: "`user_id` (eq / IN) selects which users are read.",
  args: { user_id: utf8() },
  argDefaults: { user_id: null },
  argDocs: { user_id: "Only this user (Okta id or login); NULL reads every user." },
  columns: [
    C.ctx("user_id", "The user id (or the login that was passed in).", "user_id"),
    C.str("factor_id", "Factor id.", "id", false),
    C.str("factor_type", "Factor type, e.g. push, token:software:totp, webauthn, sms, email.", "factorType"),
    C.str("provider", "Factor provider: OKTA, GOOGLE, FIDO, YUBICO, RSA, …", "provider"),
    C.str("vendor_name", "Vendor name.", "vendorName"),
    C.str("status", "ACTIVE, PENDING_ACTIVATION, NOT_SETUP, …", "status"),
    C.time("created", "Enrollment time.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
  ],
  notFoundEmpty: true,
  fanout: {
    key: "user_id",
    parents: ALL_USERS,
    parentId: idOf,
    child: (id) => ({ path: `/api/v1/users/${enc(id)}/factors`, ctx: { user_id: id } }),
  },
  examples: [
    {
      sql: `SELECT factor_type, status FROM ${Q}.user_factors(user_id := 'ada@example.com') ORDER BY factor_type`,
      description: "Factors one user has enrolled",
    },
    {
      sql: `SELECT factor_type, count(DISTINCT user_id) AS users FROM ${Q}.user_factors() WHERE status = 'ACTIVE' GROUP BY factor_type ORDER BY users DESC`,
      description: "MFA adoption by factor type",
    },
  ],
});

// ------------------------------------------------------------------------- apps

export const apps = defineOktaTable<{ q: string | null; page_size: bigint }>({
  name: "apps",
  description: "Okta application integrations",
  title: "Okta Applications",
  category: "apps",
  keywords: "okta, apps, applications, saml, oidc, sso, integrations, service providers",
  docLlm:
    "Every app integration (GET /api/v1/apps): id, name (catalog key such as 'salesforce' or 'oidc_client'), " +
    "label / app_display_name, status, sign_on_mode (SAML_2_0, OPENID_CONNECT, BOOKMARK, …), features, " +
    "created / last_updated. Credentials and settings are never returned. Filters status = and name = push " +
    "into Okta's `filter`; `q := 'sales'` searches name/label prefixes.",
  docMd: "## apps(q := NULL, page_size := 200)\n\nApplication integrations (no credentials or settings).",
  pushdown: "`status` and `name` (single eq) → `filter`.",
  args: { q: utf8(), page_size: int64() },
  argDefaults: { q: null, page_size: 200 },
  argDocs: { q: "Optional prefix search on app name and label.", page_size: PAGE_SIZE_DOC },
  argConstraints: { page_size: { ge: 1, le: 200 } },
  columns: [
    C.str("id", "App id (0oa…).", "id", false),
    C.str("name", "App catalog name, e.g. salesforce, oidc_client, bookmark.", "name"),
    C.str("label", "The app's label shown to users.", "label"),
    C.str("app_display_name", "Entra-aligned alias of label.", "label"),
    C.str("status", "ACTIVE or INACTIVE.", "status"),
    C.str(
      "sign_on_mode",
      "SAML_2_0, OPENID_CONNECT, WS_FEDERATION, BOOKMARK, AUTO_LOGIN, BROWSER_PLUGIN, …",
      "signOnMode",
    ),
    C.strList("features", "Provisioning features enabled, e.g. PUSH_NEW_USERS, IMPORT_USER_SCHEMA.", "features"),
    C.bool("hidden_on_dashboard", "Hidden from the end-user dashboard (visibility.hide.web).", "visibility.hide.web"),
    C.bool("self_service", "Self-service assignment enabled (accessibility.selfService).", "accessibility.selfService"),
    C.time("created", "When the app was added.", "created"),
    C.time("last_updated", "When the app last changed.", "lastUpdated"),
  ],
  requests: ({ args, constraints }) => [
    {
      path: "/api/v1/apps",
      query: {
        q: args.q ?? undefined,
        filter: andJoin(
          buildExpression(eqOnly(constraints), {
            status: { attr: "status", kind: "string" },
            name: { attr: "name", kind: "string" },
          }),
        ),
        limit: pageSize(args.page_size, 200),
      },
    },
  ],
  examples: [
    {
      sql: `SELECT label, sign_on_mode FROM ${Q}.apps() WHERE status = 'ACTIVE' ORDER BY label`,
      description: "Active apps and their sign-on mode",
    },
    {
      sql: `SELECT sign_on_mode, count(*) FROM ${Q}.apps() GROUP BY sign_on_mode ORDER BY 2 DESC`,
      description: "Apps by sign-on mode",
    },
  ],
});

export const appUsers = defineOktaTable<{ app_id: string | null; page_size: bigint }>({
  name: "app_users",
  description: "Users assigned to Okta apps",
  title: "Okta App User Assignments",
  category: "apps",
  keywords: "okta, app users, app assignments, provisioning, entitlements, access review",
  docLlm:
    "App user assignments (GET /api/v1/apps/{id}/users): app_id, user_id, scope (USER = direct, GROUP = via " +
    "a group), status, sync_state, user_name (the app username), external_id, timestamps and the app " +
    "profile JSON; passwords never. Pass app_id := or filter WHERE app_id = '…' / IN (…); without either " +
    "every app is read. " +
    FANOUT_NOTE,
  docMd: "## app_users(app_id := NULL, page_size := 500)\n\nApp assignments of users.",
  pushdown: "`app_id` (eq / IN) selects which apps are read.",
  args: { app_id: utf8(), page_size: int64() },
  argDefaults: { app_id: null, page_size: 500 },
  argDocs: { app_id: "Only this app (0oa…); NULL reads every app.", page_size: PAGE_SIZE_DOC },
  argConstraints: { page_size: { ge: 1, le: 500 } },
  columns: [
    C.ctx("app_id", "The app id.", "app_id"),
    C.str("user_id", "Assigned user's Okta id.", "id", false),
    C.str("scope", "USER (direct assignment) or GROUP (via group assignment).", "scope"),
    C.str("status", "Assignment status: ACTIVE, PROVISIONED, STAGED, …", "status"),
    C.str("sync_state", "Provisioning sync state: DISABLED, PENDING, SYNCHRONIZED, ERROR, …", "syncState"),
    C.str("user_name", "The user's username in the app (credentials.userName).", "credentials.userName"),
    C.str("external_id", "The user's id in the downstream app.", "externalId"),
    C.time("created", "Assignment time.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
    C.time("status_changed", "Last status change.", "statusChanged"),
    C.json("profile", "The app user profile as JSON.", "profile"),
  ],
  notFoundEmpty: true,
  fanout: {
    key: "app_id",
    parents: ALL_APPS,
    parentId: idOf,
    child: (id, { args }) => ({
      path: `/api/v1/apps/${enc(id)}/users`,
      query: { limit: pageSize(args.page_size, 500) },
      ctx: { app_id: id },
    }),
  },
  examples: [
    {
      sql: `SELECT user_name, scope FROM ${Q}.app_users(app_id := '0oa1salesforce') WHERE scope = 'USER' ORDER BY user_name`,
      description: "Users assigned directly (not via a group) to an app",
    },
    {
      sql: `SELECT a.label, count(*) AS users FROM ${Q}.app_users() au JOIN ${Q}.apps() a ON a.id = au.app_id GROUP BY ALL ORDER BY users DESC`,
      description: "Assigned users per app",
    },
  ],
});

export const appGroups = defineOktaTable<{ app_id: string | null }>({
  name: "app_groups",
  description: "Groups assigned to Okta apps",
  title: "Okta App Group Assignments",
  category: "apps",
  keywords: "okta, app groups, group assignments, entitlements",
  docLlm:
    "App group assignments (GET /api/v1/apps/{id}/groups): app_id, group_id, priority, last_updated and the " +
    "assignment profile JSON. Join group_id to groups() for names. Pass app_id := or filter on app_id; " +
    "without either every app is read. " +
    FANOUT_NOTE,
  docMd: "## app_groups(app_id := NULL)\n\nGroup assignments of apps.",
  pushdown: "`app_id` (eq / IN) selects which apps are read.",
  args: { app_id: utf8() },
  argDefaults: { app_id: null },
  argDocs: { app_id: "Only this app (0oa…); NULL reads every app." },
  columns: [
    C.ctx("app_id", "The app id.", "app_id"),
    C.str("group_id", "Assigned group's id.", "id", false),
    C.int("priority", "Assignment priority (lower wins when profiles conflict).", "priority"),
    C.time("last_updated", "Last change.", "lastUpdated"),
    C.json("profile", "Assignment profile JSON.", "profile"),
  ],
  notFoundEmpty: true,
  fanout: {
    key: "app_id",
    parents: ALL_APPS,
    parentId: idOf,
    child: (id) => ({ path: `/api/v1/apps/${enc(id)}/groups`, query: { limit: "200" }, ctx: { app_id: id } }),
  },
  examples: [
    {
      sql: `SELECT a.group_id, g.display_name FROM ${Q}.app_groups(app_id := '0oa1salesforce') a JOIN ${Q}.groups() g ON g.id = a.group_id ORDER BY g.display_name`,
      description: "Names of the groups assigned to an app",
    },
  ],
});

// ------------------------------------------------------------------ group rules

export const groupRules = defineOktaTable<{ search: string | null }>({
  name: "group_rules",
  description: "Okta group rules (dynamic membership)",
  title: "Okta Group Rules",
  category: "directory",
  keywords: "okta, group rules, dynamic groups, membership rules, expression language",
  docLlm:
    "Group rules (GET /api/v1/groups/rules): id, name, status (ACTIVE / INACTIVE / INVALID), the Okta " +
    "Expression Language condition, the target group ids, excluded users/groups, and timestamps.",
  docMd: "## group_rules(search := NULL)\n\nRules that assign users to groups automatically.",
  args: { search: utf8() },
  argDefaults: { search: null },
  argDocs: { search: "Optional keyword matched against rule names." },
  columns: [
    C.str("id", "Rule id.", "id", false),
    C.str("name", "Rule name.", "name"),
    C.str("status", "ACTIVE, INACTIVE or INVALID.", "status"),
    C.str("expression", "The Okta Expression Language condition.", "conditions.expression.value"),
    C.strList("assign_group_ids", "Groups the rule assigns users to.", "actions.assignUserToGroups.groupIds"),
    C.strList("excluded_user_ids", "Users excluded from the rule.", "conditions.people.users.exclude"),
    C.strList("excluded_group_ids", "Groups whose members are excluded.", "conditions.people.groups.exclude"),
    C.time("created", "When created.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
  ],
  requests: ({ args }) => [{ path: "/api/v1/groups/rules", query: { search: args.search ?? undefined, limit: "200" } }],
  examples: [
    {
      sql: `SELECT name, expression FROM ${Q}.group_rules() WHERE status = 'INVALID' ORDER BY name`,
      description: "Broken group rules",
    },
  ],
});

// --------------------------------------------------------------------- policies

export const POLICY_TYPES = [
  "OKTA_SIGN_ON",
  "PASSWORD",
  "MFA_ENROLL",
  "IDP_DISCOVERY",
  "ACCESS_POLICY",
  "PROFILE_ENROLLMENT",
];

export const policies = defineOktaCatalogTable({
  name: "policies",
  description: "Okta policies of every type (summary)",
  title: "Okta Policies",
  category: "security",
  keywords: "okta, policies, sign-on policy, password policy, mfa enrollment, authentication policy, access policy",
  docLlm:
    "Policies (GET /api/v1/policies?type=…) for OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, IDP_DISCOVERY, " +
    "ACCESS_POLICY (app authentication policies) and PROFILE_ENROLLMENT: id, type, name, description, status, " +
    "priority, system, timestamps and the conditions JSON. Filter `type = '…'` (or IN) to call only those " +
    "types; `status = 'ACTIVE'` is sent to Okta too. Use policy_rules(id) for each policy's rules.",
  docMd: "## policies\n\nOne row per policy across the policy types (a table: no parentheses).",
  pushdown: "`type` (eq / IN) selects which policy types are listed; `status` (eq) → `status`.",
  columns: [
    C.str("id", "Policy id.", "id", false),
    C.str("type", "Policy type.", "type"),
    C.str("name", "Policy name.", "name"),
    C.str("description", "Admin-written explanation of what the policy is for.", "description"),
    C.str("status", "ACTIVE or INACTIVE.", "status"),
    C.int("priority", "Evaluation priority (1 = first).", "priority"),
    C.bool("system", "True for Okta's built-in default policy.", "system"),
    C.time("created", "When created.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
    C.json("conditions", "Policy conditions (people, network, …) as JSON.", "conditions"),
  ],
  requests: ({ constraints }) => {
    const types = eqValues(constraints, "type")?.filter((t) => /^[A-Z_]+$/.test(t)) ?? POLICY_TYPES;
    const status = eqValues(constraints, "status");
    return types.map((t) => ({
      path: "/api/v1/policies",
      query: { type: t, status: status?.length === 1 ? status[0] : undefined, limit: "200" },
    }));
  },
  examples: [
    {
      sql: `SELECT type, name, priority FROM ${Q}.policies WHERE status = 'ACTIVE' ORDER BY type, priority`,
      description: "Active policies in evaluation order",
    },
    {
      sql: `SELECT name FROM ${Q}.policies WHERE type = 'PASSWORD' ORDER BY priority`,
      description: "Password policies only (one API call)",
    },
  ],
});

export const policyRules = defineOktaTable<{ policy_id: string | null }>({
  name: "policy_rules",
  description: "Rules of Okta policies (summary)",
  title: "Okta Policy Rules",
  category: "security",
  keywords: "okta, policy rules, sign-on rules, authentication rules, mfa",
  docLlm:
    "Policy rules (GET /api/v1/policies/{id}/rules): policy_id, id, name, type, status, priority, system, " +
    "timestamps, and the conditions and actions as JSON. Pass policy_id := or filter on policy_id; without " +
    "either the rules of every policy (of every type in the policies table) are read. " +
    FANOUT_NOTE,
  docMd: "## policy_rules(policy_id := NULL)\n\nRules for policies.",
  pushdown: "`policy_id` (eq / IN) selects which policies are read.",
  args: { policy_id: utf8() },
  argDefaults: { policy_id: null },
  argDocs: { policy_id: "Only this policy (from the policies table); NULL reads every policy." },
  columns: [
    C.ctx("policy_id", "The policy id.", "policy_id"),
    C.str("id", "Rule id.", "id", false),
    C.str("name", "Rule name.", "name"),
    C.str("type", "Rule type, e.g. SIGN_ON, PASSWORD, ACCESS_POLICY.", "type"),
    C.str("status", "ACTIVE or INACTIVE.", "status"),
    C.int("priority", "Evaluation priority.", "priority"),
    C.bool("system", "True for the built-in catch-all rule.", "system"),
    C.time("created", "When created.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
    C.json("conditions", "Rule conditions as JSON.", "conditions"),
    C.json("actions", "Rule actions (e.g. MFA requirement, session lifetime) as JSON.", "actions"),
  ],
  notFoundEmpty: true,
  fanout: {
    key: "policy_id",
    parents: POLICY_TYPES.map((t) => ({ path: "/api/v1/policies", query: { type: t, limit: "200" } })),
    parentId: idOf,
    child: (id) => ({ path: `/api/v1/policies/${enc(id)}/rules`, ctx: { policy_id: id } }),
  },
  examples: [
    {
      sql: `SELECT p.name AS policy, r.name AS rule, r.status FROM ${Q}.policy_rules() r JOIN ${Q}.policies p ON p.id = r.policy_id WHERE p.type = 'OKTA_SIGN_ON' ORDER BY ALL`,
      description: "Every global session policy rule",
    },
    {
      sql: `SELECT name, priority, actions->'signon'->>'requireFactor' AS mfa FROM ${Q}.policy_rules(policy_id := '00p1signon') ORDER BY priority`,
      description: "Whether each rule of one policy requires MFA",
    },
  ],
});

// --------------------------------------------------------- authorization servers

export const authorizationServers = defineOktaTable<{ q: string | null }>({
  name: "authorization_servers",
  description: "Okta custom authorization servers (summary)",
  title: "Okta Authorization Servers",
  category: "security",
  keywords: "okta, authorization servers, oauth, oidc, issuer, audiences, signing keys",
  docLlm:
    "Custom authorization servers (GET /api/v1/authorizationServers): id, name, description, audiences, " +
    "issuer, issuer_mode, status, signing key rotation (mode, kid, last/next rotation) and timestamps.",
  docMd: "## authorization_servers(q := NULL)\n\nCustom OAuth 2.0 / OIDC authorization servers.",
  args: { q: utf8() },
  argDefaults: { q: null },
  argDocs: { q: "Optional name prefix search." },
  columns: [
    C.str("id", "Authorization server id (aus…, or 'default').", "id", false),
    C.str("name", "Name.", "name"),
    C.str("description", "Admin-written description of the authorization server.", "description"),
    C.strList("audiences", "Accepted token audiences.", "audiences"),
    C.str("issuer", "Issuer URL.", "issuer"),
    C.str("issuer_mode", "ORG_URL, CUSTOM_URL or DYNAMIC.", "issuerMode"),
    C.str("status", "ACTIVE or INACTIVE.", "status"),
    C.str("signing_rotation_mode", "AUTO or MANUAL.", "credentials.signing.rotationMode"),
    C.str("signing_kid", "Current signing key id.", "credentials.signing.kid"),
    C.time("signing_last_rotated", "Last key rotation.", "credentials.signing.lastRotated"),
    C.time("signing_next_rotation", "Next scheduled rotation.", "credentials.signing.nextRotation"),
    C.time("created", "When created.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
  ],
  requests: ({ args }) => [{ path: "/api/v1/authorizationServers", query: { q: args.q ?? undefined, limit: "200" } }],
  examples: [
    {
      sql: `SELECT name, issuer, signing_next_rotation FROM ${Q}.authorization_servers() WHERE status = 'ACTIVE' ORDER BY name`,
      description: "Active authorization servers and their next key rotation",
    },
  ],
});

// ------------------------------------------------------- admin role assignments

/** Attach principal info to role rows. */
const withPrincipal = (rows: Row[], type: string, id: string): Row[] =>
  rows.map((r) => ({ ...r, _principal_type: type, _principal_id: id }));

export const adminRoleAssignments = defineOktaTable<{ user_id: string | null; group_id: string | null }>({
  name: "admin_role_assignments",
  description: "Okta administrator role assignments",
  title: "Okta Admin Role Assignments",
  category: "security",
  keywords: "okta, admin roles, administrators, super admin, privileged access, rbac, role assignments",
  docLlm:
    "Administrator role assignments. With no arguments, lists every user holding an admin role " +
    "(GET /api/v1/iam/assignees/users) and that user's roles (GET /api/v1/users/{id}/roles). " +
    "`user_id := '…'` returns one user's roles; `group_id := '…'` returns a group's roles " +
    "(GET /api/v1/groups/{id}/roles). Columns: principal_type (USER / GROUP), principal_id, assignment id, " +
    "role_type (SUPER_ADMIN, ORG_ADMIN, APP_ADMIN, USER_ADMIN, HELP_DESK_ADMIN, READ_ONLY_ADMIN, CUSTOM, …), " +
    "role_label, status, assignment_type (USER = direct, GROUP = via group), and timestamps.",
  docMd:
    "## admin_role_assignments(user_id := NULL, group_id := NULL)\n\nWho holds which Okta admin role. " +
    "Without arguments every admin user is listed (users who are admins only through a group appear with " +
    "assignment_type = 'GROUP').",
  args: { user_id: utf8(), group_id: utf8() },
  argDefaults: { user_id: null, group_id: null },
  argDocs: {
    user_id: "Only this user's roles (id or login).",
    group_id: "Only this group's roles.",
  },
  columns: [
    C.str("principal_type", "USER or GROUP.", (r) => r._principal_type),
    C.str("principal_id", "The user or group id holding the role.", (r) => r._principal_id),
    C.str("assignment_id", "Role assignment id.", "id", false),
    C.str("role_type", "Role type, e.g. SUPER_ADMIN, ORG_ADMIN, APP_ADMIN, CUSTOM.", "type"),
    C.str("role_label", "Role label.", "label"),
    C.str("status", "ACTIVE or INACTIVE.", "status"),
    C.str("assignment_type", "USER (direct) or GROUP (inherited from a group).", "assignmentType"),
    C.str("resource_set", "Resource set id (custom roles).", "resource-set"),
    C.str("custom_role_id", "Custom role id (custom roles).", "role"),
    C.time("created", "When assigned.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
  ],
  notFoundEmpty: true,
  requests: ({ args }) => {
    if (args.user_id)
      return [{ path: `/api/v1/users/${enc(args.user_id)}/roles`, ctx: { t: "USER", id: args.user_id } }];
    if (args.group_id)
      return [{ path: `/api/v1/groups/${enc(args.group_id)}/roles`, ctx: { t: "GROUP", id: args.group_id } }];
    return [{ path: "/api/v1/iam/assignees/users", query: { limit: "100" }, ctx: { t: "ASSIGNEES" } }];
  },
  rows: (body) => {
    if (Array.isArray(body)) return body as Row[];
    const v = (body as { value?: unknown })?.value;
    return Array.isArray(v) ? (v as Row[]) : [];
  },
  expand: async (cfg: OktaConfig, rows: Row[], ctx) => {
    if (ctx.t !== "ASSIGNEES") return withPrincipal(rows, ctx.t ?? "USER", ctx.id ?? "");
    const out: Row[] = [];
    for (const assignee of rows) {
      const id = asStr(assignee.id);
      if (!id) continue;
      out.push(...withPrincipal(await getAll(cfg, `/api/v1/users/${enc(id)}/roles`), "USER", id));
    }
    return out;
  },
  examples: [
    {
      sql: `SELECT role_type, count(DISTINCT principal_id) AS admins FROM ${Q}.admin_role_assignments() GROUP BY role_type ORDER BY admins DESC`,
      description: "How many users hold each admin role",
    },
    {
      sql: `SELECT u.login, r.assignment_type FROM ${Q}.admin_role_assignments() r JOIN ${Q}.users() u ON u.id = r.principal_id WHERE r.role_type = 'SUPER_ADMIN' ORDER BY u.login`,
      description: "Super administrators by login",
    },
  ],
});

// ---------------------------------------------------------------------- devices

const DEVICE_ATTRS: Record<string, AttrMap> = {
  id: { attr: "id", kind: "string" },
  status: { attr: "status", kind: "string" },
  account_enabled: { attr: "status", kind: "bool", value: (v) => (v === true ? "ACTIVE" : undefined) },
  operating_system: { attr: "profile.platform", kind: "string" },
  display_name: { attr: "profile.displayName", kind: "string", prefix: true },
  last_updated: { attr: "lastUpdated", kind: "time", range: true },
  created: { attr: "created", kind: "time", range: true },
};

export const devices = defineOktaTable<{ search: string | null; page_size: bigint }>({
  name: "devices",
  description: "Devices registered with Okta (Okta Verify / FastPass)",
  title: "Okta Devices",
  category: "directory",
  keywords: "okta, devices, endpoints, okta verify, fastpass, platform, macos, windows, ios, android",
  docLlm:
    "Registered devices (GET /api/v1/devices?expand=user): id, status, account_enabled, display_name, " +
    "operating_system (platform: WINDOWS / MACOS / IOS / ANDROID / CHROMEOS), os_version, manufacturer, model, " +
    "serial_number, registered, secure_hardware_present, disk_encryption_type, the ids of the users the " +
    "device is linked to, and timestamps. Filters on status, operating_system, display_name, id and " +
    "timestamps push into Okta's `search`.",
  docMd:
    "## devices(search := NULL, page_size := 200)\n\nDevices, Entra-aligned (`display_name`, `operating_system`, `account_enabled`).",
  pushdown:
    "`id`, `status`, `account_enabled = true`, `operating_system`, `display_name` (eq / IN / starts_with), timestamp ranges → `search`.",
  args: { search: utf8(), page_size: int64() },
  argDefaults: { search: null, page_size: 200 },
  argDocs: {
    search: "Optional raw Okta device search expression ANDed with pushed filters.",
    page_size: PAGE_SIZE_DOC,
  },
  argConstraints: { page_size: { ge: 1, le: 200 } },
  columns: [
    C.str("id", "Device id (guo…).", "id", false),
    C.str("status", "ACTIVE, CREATED, DEACTIVATED or SUSPENDED.", "status"),
    C.bool("account_enabled", "Entra-aligned: true when status is ACTIVE.", (r) =>
      typeof r.status === "string" ? r.status === "ACTIVE" : null,
    ),
    C.str("display_name", "Device name (profile.displayName).", "profile.displayName"),
    C.str("operating_system", "Platform: WINDOWS, MACOS, IOS, ANDROID, CHROMEOS.", "profile.platform"),
    C.str("os_version", "OS version.", "profile.osVersion"),
    C.str("manufacturer", "Manufacturer.", "profile.manufacturer"),
    C.str("model", "Model.", "profile.model"),
    C.str("serial_number", "Serial number.", "profile.serialNumber"),
    C.bool("registered", "Registered with Okta.", "profile.registered"),
    C.bool("secure_hardware_present", "TPM / Secure Enclave present.", "profile.secureHardwarePresent"),
    C.str("disk_encryption_type", "ALL_INTERNAL_VOLUMES, USER, NONE, …", "profile.diskEncryptionType"),
    C.strList("user_ids", "Okta users linked to the device.", (r) =>
      Array.isArray(r._embedded?.users) ? r._embedded.users.map((u: Row) => u?.user?.id).filter(Boolean) : null,
    ),
    C.time("created", "When registered.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
  ],
  requests: ({ args, constraints }) => [
    {
      path: "/api/v1/devices",
      query: {
        search: andJoin(buildExpression(constraints, DEVICE_ATTRS), args.search),
        expand: "user",
        limit: pageSize(args.page_size, 200),
      },
    },
  ],
  examples: [
    {
      sql: `SELECT operating_system, count(*) AS devices FROM ${Q}.devices() WHERE status = 'ACTIVE' GROUP BY operating_system ORDER BY devices DESC`,
      description: "Active devices by platform",
    },
    {
      sql: `SELECT display_name, os_version FROM ${Q}.devices() WHERE operating_system = 'MACOS' AND NOT secure_hardware_present ORDER BY display_name`,
      description: "Macs without secure hardware",
    },
  ],
});

// ---------------------------------------------------------------- network zones

export const networkZones = defineOktaCatalogTable({
  name: "network_zones",
  description: "Okta network zones (IP, dynamic and enhanced dynamic)",
  title: "Okta Network Zones",
  category: "security",
  keywords: "okta, network zones, ip allowlist, blocklist, cidr, geolocation, asn, proxies",
  docLlm:
    "Network zones (GET /api/v1/zones): id, name, type (IP, DYNAMIC, DYNAMIC_V2), status, usage (POLICY or " +
    "BLOCKLIST), system, gateway and proxy CIDRs/ranges, locations (country or country-region codes), ASNs, " +
    "proxy_type and timestamps. `usage = '…'` and `id = '…'` push into Okta's `filter`.",
  docMd: "## network_zones\n\nNetwork zones used by policies and blocklists (a table: no parentheses).",
  pushdown: "`usage` or `id` (single eq) → `filter`.",
  columns: [
    C.str("id", "Zone id (nzo…).", "id", false),
    C.str("name", "Zone name.", "name"),
    C.str("type", "IP, DYNAMIC or DYNAMIC_V2.", "type"),
    C.str("status", "ACTIVE or INACTIVE.", "status"),
    C.str("usage", "POLICY or BLOCKLIST.", "usage"),
    C.bool("system", "True for Okta's built-in zones (e.g. LegacyIpZone).", "system"),
    C.strList("gateways", "Gateway CIDRs or ranges.", (r) =>
      Array.isArray(r.gateways) ? r.gateways.map((g: Row) => g?.value) : null,
    ),
    C.strList("proxies", "Trusted proxy CIDRs or ranges.", (r) =>
      Array.isArray(r.proxies) ? r.proxies.map((g: Row) => g?.value) : null,
    ),
    C.strList("locations", "Locations as 'CC' or 'CC-RR' codes.", (r) =>
      Array.isArray(r.locations)
        ? r.locations.map((l: Row) => (l?.region ? String(l.region) : String(l?.country ?? "")))
        : null,
    ),
    C.strList("asns", "Autonomous system numbers.", "asns"),
    C.str("proxy_type", "Proxy type for dynamic zones: ANY, TOR, NOT_TOR, null.", "proxyType"),
    C.time("created", "When created.", "created"),
    C.time("last_updated", "Last change.", "lastUpdated"),
  ],
  requests: ({ constraints }) => {
    const parts = buildExpression(eqOnly(constraints), {
      usage: { attr: "usage", kind: "string" },
      id: { attr: "id", kind: "string" },
    });
    // The zones filter accepts a single expression; send only the first.
    return [{ path: "/api/v1/zones", query: { filter: parts[0], limit: "200" } }];
  },
  examples: [
    {
      sql: `SELECT name, gateways FROM ${Q}.network_zones WHERE usage = 'BLOCKLIST' ORDER BY name`,
      description: "Blocklisted zones and their CIDRs",
    },
  ],
});

// ------------------------------------------------------------------- system log

/** Okta keeps System Log events for 90 days; a `since` older than that is rejected. */
export const RETENTION_DAYS = 90;
const DAY = 86_400_000;

const LOG_ATTRS: Record<string, AttrMap> = {
  uuid: { attr: "uuid", kind: "string" },
  id: { attr: "uuid", kind: "string" },
  event_type: { attr: "eventType", kind: "string", prefix: true },
  severity: { attr: "severity", kind: "string" },
  actor_id: { attr: "actor.id", kind: "string" },
  actor_alternate_id: { attr: "actor.alternateId", kind: "string" },
  actor_type: { attr: "actor.type", kind: "string" },
  outcome_result: { attr: "outcome.result", kind: "string" },
  status: { attr: "outcome.result", kind: "string" },
  ip_address: { attr: "client.ipAddress", kind: "string" },
  transaction_id: { attr: "transaction.id", kind: "string" },
};

/**
 * The [since, until) window a system_log scan requests: pushed `published` /
 * `created_date_time` bounds, else `lookback_days` before the scan started; clamped to
 * the 90-day retention and to the scan start, so every request is bounded.
 */
export function logWindow(
  constraints: Constraint[],
  lookbackDays: number,
  anchorMs: number,
): { since: number; until: number } | null {
  const a = timeBounds(constraints, "published");
  const b = timeBounds(constraints, "created_date_time");
  const lowers = [a.lower, b.lower].filter((x): x is number => x !== undefined);
  const uppers = [a.upper, b.upper].filter((x): x is number => x !== undefined);
  const floor = anchorMs - RETENTION_DAYS * DAY + 60_000;
  const since = Math.max(lowers.length ? Math.max(...lowers) : anchorMs - lookbackDays * DAY, floor);
  const until = Math.min(uppers.length ? Math.min(...uppers) : anchorMs, anchorMs);
  return since < until ? { since, until } : null;
}

const appTarget = (r: Row): string | null => {
  const t = Array.isArray(r.target) ? r.target.find((x: Row) => x?.type === "AppInstance") : undefined;
  return t?.displayName ?? null;
};

export const systemLog = defineOktaTable<{
  q: string | null;
  filter_expr: string | null;
  lookback_days: bigint;
  sort_order: string;
  page_size: bigint;
}>({
  name: "system_log",
  description: "Okta System Log events, with time window and filters pushed down",
  title: "Okta System Log",
  category: "audit",
  keywords: "okta, system log, audit log, events, sign-in, authentication, siem, security, logs",
  docLlm:
    "Okta System Log events (GET /api/v1/logs) — sign-ins, MFA, admin changes, provisioning. Columns: uuid " +
    "(also id), published (also created_date_time), event_type, display_message, severity, actor (id, type, " +
    "alternate_id, display_name; user_principal_name when the actor is a user), outcome_result (also status) " +
    "and outcome_reason, client ip_address / user agent / OS / browser / zone, geo city/state/country/lat/lon, " +
    "app_display_name (first AppInstance target), targets (list of structs), transaction_id, " +
    "external_session_id and debug_data JSON. ALWAYS filter on published: `published >= / > / < / <=` become " +
    "Okta's since/until; without one the last `lookback_days` (default 7) are read. Okta retains 90 days, so " +
    "older lower bounds are clamped to the retention window. Filters on event_type (eq / IN / starts_with), " +
    "actor_id, actor_alternate_id, actor_type, outcome_result / status, severity, ip_address, transaction_id " +
    "and uuid become Okta's `filter` expression; `q := 'word'` adds keyword search and " +
    "`filter_expr := '…'` a raw filter expression.",
  docMd:
    "## system_log(q := NULL, filter_expr := NULL, lookback_days := 7, sort_order := 'ASCENDING', page_size := 1000)\n\n" +
    "Okta System Log events. Columns align with the Entra sign-in/audit workers (`created_date_time`, " +
    "`user_principal_name`, `app_display_name`, `ip_address`, `status`).",
  pushdown:
    "`published`/`created_date_time` ranges → `since`/`until` (clamped to 90-day retention; always bounded by the " +
    "scan start); `event_type` (eq, IN, starts_with), `actor_id`, `actor_alternate_id`, `actor_type`, " +
    "`outcome_result`/`status`, `severity`, `ip_address`, `transaction_id`, `uuid`/`id` → `filter`.",
  args: { q: utf8(), filter_expr: utf8(), lookback_days: int64(), sort_order: utf8(), page_size: int64() },
  argDefaults: { q: null, filter_expr: null, lookback_days: 7, sort_order: "ASCENDING", page_size: 1000 },
  argDocs: {
    q: "Optional keyword search (space-separated terms, all must match).",
    filter_expr: "Optional raw System Log filter expression ANDed with pushed filters, e.g. 'target.id eq \"00u1\"'.",
    lookback_days: "Days before now to read when no lower bound on published is given (1–90).",
    sort_order: "ASCENDING (oldest first) or DESCENDING (newest first).",
    page_size: "Events per page (max 1000).",
  },
  argConstraints: {
    lookback_days: { ge: 1, le: RETENTION_DAYS },
    sort_order: { choices: ["ASCENDING", "DESCENDING"] },
    page_size: { ge: 1, le: 1000 },
  },
  columns: [
    C.str("uuid", "Event id.", "uuid", false),
    C.str("id", "Entra-aligned alias of uuid.", "uuid"),
    C.time("published", "When the event happened.", "published"),
    C.time("created_date_time", "Entra-aligned alias of published.", "published"),
    C.str(
      "event_type",
      "Event type, e.g. user.session.start, user.authentication.auth_via_mfa, policy.lifecycle.update.",
      "eventType",
    ),
    C.str("display_message", "Human-readable summary.", "displayMessage"),
    C.str("severity", "DEBUG, INFO, WARN or ERROR.", "severity"),
    C.str("actor_id", "Actor id.", "actor.id"),
    C.str("actor_type", "Actor type: User, SystemPrincipal, PublicClientApp, …", "actor.type"),
    C.str("actor_alternate_id", "Actor alternate id (a user's login).", "actor.alternateId"),
    C.str("actor_display_name", "Actor display name.", "actor.displayName"),
    C.str("user_principal_name", "Entra-aligned: the actor's login when the actor is a User.", (r) =>
      r.actor?.type === "User" ? r.actor?.alternateId : null,
    ),
    C.str("outcome_result", "SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, CHALLENGE or UNKNOWN.", "outcome.result"),
    C.str("status", "Entra-aligned alias of outcome_result.", "outcome.result"),
    C.str("outcome_reason", "Why the outcome happened, e.g. INVALID_CREDENTIALS.", "outcome.reason"),
    C.str("ip_address", "Client IP address.", "client.ipAddress"),
    C.str("client_user_agent", "Raw user agent.", "client.userAgent.rawUserAgent"),
    C.str("client_os", "Client OS.", "client.userAgent.os"),
    C.str("client_browser", "Client browser.", "client.userAgent.browser"),
    C.str("client_device", "Client device type.", "client.device"),
    C.str("client_zone", "Network zone the client matched.", "client.zone"),
    C.str("geo_city", "City.", "client.geographicalContext.city"),
    C.str("geo_state", "State / region.", "client.geographicalContext.state"),
    C.str("geo_country", "Country.", "client.geographicalContext.country"),
    C.num("geo_lat", "Latitude.", "client.geographicalContext.geolocation.lat"),
    C.num("geo_lon", "Longitude.", "client.geographicalContext.geolocation.lon"),
    C.str("app_display_name", "Entra-aligned: display name of the first AppInstance target.", appTarget),
    C.structList(
      "targets",
      "Event targets (users, apps, groups, policies …).",
      "STRUCT(id VARCHAR, type VARCHAR, alternate_id VARCHAR, display_name VARCHAR)[]",
      [
        { name: "id", path: "id" },
        { name: "type", path: "type" },
        { name: "alternate_id", path: "alternateId" },
        { name: "display_name", path: "displayName" },
      ],
      "target",
    ),
    C.str("transaction_id", "Request/transaction id grouping related events.", "transaction.id"),
    C.str(
      "external_session_id",
      "Session id (authenticationContext.externalSessionId).",
      "authenticationContext.externalSessionId",
    ),
    C.str("authentication_step", "Authentication step number.", (r) => r.authenticationContext?.authenticationStep),
    C.json("debug_data", "debugContext.debugData as JSON (risk, behaviors, request URI …).", "debugContext.debugData"),
  ],
  requests: ({ args, constraints, anchorMs }) => {
    const w = logWindow(constraints, Number(args.lookback_days ?? 7), anchorMs);
    if (!w) return [];
    return [
      {
        path: "/api/v1/logs",
        query: {
          since: oktaTime(w.since),
          until: oktaTime(w.until),
          filter: andJoin(buildExpression(constraints, LOG_ATTRS), args.filter_expr),
          q: args.q ?? undefined,
          sortOrder: args.sort_order ?? "ASCENDING",
          limit: pageSize(args.page_size, 1000),
        },
      },
    ];
  },
  examples: [
    {
      sql: `SELECT actor_alternate_id, count(*) AS failures FROM ${Q}.system_log() WHERE published >= TIMESTAMPTZ '2026-11-01 00:00:00+00' AND event_type = 'user.session.start' AND outcome_result = 'FAILURE' GROUP BY 1 ORDER BY failures DESC LIMIT 20`,
      description: "Users with the most failed sign-ins since a date (window and filters pushed to Okta)",
    },
    {
      sql: `SELECT published, event_type, display_message FROM ${Q}.system_log(sort_order := 'DESCENDING') WHERE starts_with(event_type, 'policy.') ORDER BY published DESC LIMIT 50`,
      description: "Latest policy changes in the last 7 days",
    },
  ],
});

export const FUNCTIONS: VgiFunction[] = [
  users,
  getUser,
  userGroups,
  userFactors,
  groups,
  groupMembers,
  groupRules,
  apps,
  appUsers,
  appGroups,
  policyRules,
  authorizationServers,
  adminRoleAssignments,
  devices,
  systemLog,
];

/** Parameterless collections, exposed as catalog tables. */
export const TABLES = [policies, networkZones];
