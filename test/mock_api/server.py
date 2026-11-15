#!/usr/bin/env python3
"""An offline Okta Management API replay server for the tests (stdlib only).

It serves the hand-built org in ``test/fixtures/okta-org.json`` (documented Okta
response shapes) and behaves like Okta where the worker depends on it:

* **Auth.** ``Authorization: SSWS test-token``, or ``Bearer <token>`` minted by
  ``POST /oauth2/v1/token`` after verifying a ``private_key_jwt`` client assertion
  (ES256 or RS256 signature against the public keys in
  ``test/fixtures/service-app-public-jwks.json``; aud/iss/sub/exp/jti checked; scopes
  enforced per endpoint). Anything else gets Okta's 401 ``E0000011``.
* **Query validation.** Each route accepts only its documented parameters; an unknown
  parameter, a bad ``limit`` or an unparsable/unsupported ``search``/``filter``
  expression is a 400 ``E0000031`` / ``E0000001``. Expressions are actually evaluated
  (eq/ne/gt/ge/lt/le/sw/co/ew/pr, and/or/not, parentheses; string comparisons are
  case-insensitive like Okta's), so pushdown really narrows the data.
* **Paging.** ``limit`` + opaque ``after`` cursors, returned as ``Link: <…>; rel="next"``.
  System Log polling semantics: an ASCENDING request without ``until`` always carries a
  next link, as Okta's does.
* **System Log.** ``since``/``until`` bounds (``since`` defaults to 7 days ago and must be
  within the 90-day retention, else 400), ``filter``, ``q``, ``sortOrder``. Event times
  are offsets before server start so the fixture never ages out.
* **Rate limits.** ``X-Rate-Limit-Limit/-Remaining/-Reset`` on every response; the first
  ``/api/v1/groups/rules`` request answers 429 (bucket empty, reset in 1 s) and the
  first ``/api/v1/zones`` request answers 503, so the retry paths always run.
* **Introspection.** ``GET /__requests?path=/api/v1/users`` returns every recorded
  request to that path (``seq``, ``path``, ``query`` as a JSON object string,
  ``auth``), so SQL tests can assert exactly what was pushed down.

Usage::

    python3 test/mock_api/server.py            # prints PORT:<n> once listening
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import json
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures"
ORG = json.loads((FIXTURES / "okta-org.json").read_text())
JWKS = json.loads((FIXTURES / "service-app-public-jwks.json").read_text())
FIXTURE_ORIGIN = "https://acme.okta.com"
API_TOKEN = "test-token"
SERVICE_APPS = {"0oaserviceappec": JWKS["ec"], "0oaserviceapprsa": JWKS["rsa"]}
ALL_SCOPES = {
    "okta.users.read", "okta.groups.read", "okta.apps.read", "okta.logs.read", "okta.policies.read",
    "okta.authorizationServers.read", "okta.roles.read", "okta.devices.read", "okta.networkZones.read",
    "okta.factors.read",
}
START = dt.datetime.now(dt.timezone.utc)
RETENTION = dt.timedelta(days=90)

LOCK = threading.Lock()
REQUESTS: list[dict] = []
TOKENS: dict[str, set[str]] = {}
SEEN_JTI: set[str] = set()
ONCE: set[str] = set()


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


for _e in ORG["logs"]:
    _e["published"] = iso(START - dt.timedelta(minutes=_e.pop("published_offset_minutes")))


def parse_time(v: object) -> dt.datetime | None:
    if not isinstance(v, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T", v):
        return None
    try:
        return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


class ApiError(Exception):
    def __init__(self, status: int, code: str, summary: str, headers: dict | None = None):
        super().__init__(summary)
        self.status, self.code, self.summary, self.headers = status, code, summary, headers or {}


def bad_request(summary: str, code: str = "E0000001") -> ApiError:
    return ApiError(400, code, f"Api validation failed: {summary}")


# ------------------------------------------------------------- expression evaluator

TOKEN_RE = re.compile(r'\s*(?:(\()|(\))|"((?:[^"\\]|\\.)*)"|([A-Za-z_][\w.\-]*)|(-?\d+(?:\.\d+)?))')
OPS = {"eq", "ne", "gt", "ge", "lt", "le", "sw", "co", "ew", "pr"}


def tokenize(s: str) -> list[tuple[str, object]]:
    pos, out = 0, []
    while pos < len(s):
        if s[pos:].strip() == "":
            break
        m = TOKEN_RE.match(s, pos)
        if not m or m.end() == pos:
            raise bad_request(f"Invalid search criteria near: {s[pos:pos + 20]!r}", "E0000031")
        pos = m.end()
        if m.group(1):
            out.append(("(", None))
        elif m.group(2):
            out.append((")", None))
        elif m.group(3) is not None:
            out.append(("str", re.sub(r"\\(.)", r"\1", m.group(3))))
        elif m.group(4):
            w = m.group(4)
            out.append(("word", w))
        else:
            out.append(("num", float(m.group(5))))
    return out


def parse_expr(s: str, allowed: tuple[str, ...]):
    toks = tokenize(s)
    i = 0

    def peek():
        return toks[i] if i < len(toks) else (None, None)

    def take():
        nonlocal i
        t = peek()
        i += 1
        return t

    def attr_ok(a: str) -> bool:
        return any(a == p or (p.endswith(".*") and a.startswith(p[:-1])) for p in allowed)

    def expr():
        node = term()
        while peek() == ("word", "or"):
            take()
            node = ("or", node, term())
        return node

    def term():
        node = factor()
        while peek() == ("word", "and"):
            take()
            node = ("and", node, factor())
        return node

    def factor():
        t = take()
        if t == ("word", "not"):
            return ("not", factor())
        if t[0] == "(":
            node = expr()
            if take()[0] != ")":
                raise bad_request("Invalid search criteria: missing ')'", "E0000031")
            return node
        if t[0] != "word":
            raise bad_request(f"Invalid search criteria: expected attribute, got {t[1]!r}", "E0000031")
        attr = str(t[1])
        if not attr_ok(attr):
            raise bad_request(f"Invalid search criteria: unsupported attribute {attr!r}", "E0000031")
        op = take()
        if op[0] != "word" or op[1] not in OPS:
            raise bad_request(f"Invalid search criteria: bad operator {op[1]!r}", "E0000031")
        if op[1] == "pr":
            return ("pr", attr)
        v = take()
        if v[0] == "str" or v[0] == "num":
            val = v[1]
        elif v == ("word", "true") or v == ("word", "false"):
            val = v[1] == "true"
        elif v == ("word", "null"):
            val = None
        else:
            raise bad_request(f"Invalid search criteria: bad value {v[1]!r}", "E0000031")
        return ("cmp", attr, op[1], val)

    node = expr()
    if i != len(toks):
        raise bad_request("Invalid search criteria: trailing tokens", "E0000031")
    return node


def resolve(obj: object, path: str) -> object:
    cur = obj
    for p in path.split("."):
        if isinstance(cur, list):  # target.id etc. — any element
            vals = [resolve(x, p) for x in cur]
            return vals
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def compare(actual: object, op: str, want: object) -> bool:
    if isinstance(actual, list):
        return any(compare(a, op, want) for a in actual)
    if actual is None:
        return op == "ne" and want is not None
    ta, tw = parse_time(actual), parse_time(want)
    if ta and tw:
        a, w = ta, tw
    elif isinstance(actual, bool) or isinstance(want, bool):
        a, w = actual, want
    elif isinstance(actual, (int, float)) and isinstance(want, (int, float)):
        a, w = actual, want
    else:
        a, w = str(actual).lower(), str(want).lower()
    if op == "eq":
        return a == w
    if op == "ne":
        return a != w
    if op == "sw":
        return str(a).startswith(str(w))
    if op == "co":
        return str(w) in str(a)
    if op == "ew":
        return str(a).endswith(str(w))
    try:
        return {"gt": a > w, "ge": a >= w, "lt": a < w, "le": a <= w}[op]  # type: ignore[operator]
    except TypeError:
        return False


def evaluate(node, obj) -> bool:
    kind = node[0]
    if kind == "or":
        return evaluate(node[1], obj) or evaluate(node[2], obj)
    if kind == "and":
        return evaluate(node[1], obj) and evaluate(node[2], obj)
    if kind == "not":
        return not evaluate(node[1], obj)
    if kind == "pr":
        v = resolve(obj, node[1])
        return v not in (None, "", [])
    return compare(resolve(obj, node[1]), node[2], node[3])


def where(items: list, expr: str | None, allowed: tuple[str, ...]) -> list:
    if not expr:
        return items
    node = parse_expr(expr, allowed)
    return [x for x in items if evaluate(node, x)]


# ---------------------------------------------------------------------- JWT / keys


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_A = P256_P - 3
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P256_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + P256_A) * pow(2 * p[1], -1, P256_P)
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P256_P)
    lam %= P256_P
    x = (lam * lam - p[0] - q[0]) % P256_P
    return (x, (lam * (p[0] - x) - p[1]) % P256_P)


def ec_mul(k, p):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, p)
        p = ec_add(p, p)
        k >>= 1
    return r


def verify_es256(jwk: dict, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    r, s = b2i(sig[:32]), b2i(sig[32:])
    if not (0 < r < P256_N and 0 < s < P256_N):
        return False
    q = (b2i(b64d(jwk["x"])), b2i(b64d(jwk["y"])))
    z = b2i(hashlib.sha256(msg).digest())
    w = pow(s, -1, P256_N)
    pt = ec_add(ec_mul(z * w % P256_N, P256_G), ec_mul(r * w % P256_N, q))
    return pt is not None and pt[0] % P256_N == r


SHA256_DER = bytes.fromhex("3031300d060960864801650304020105000420")


def verify_rs256(jwk: dict, msg: bytes, sig: bytes) -> bool:
    n, e = b2i(b64d(jwk["n"])), b2i(b64d(jwk["e"]))
    k = (n.bit_length() + 7) // 8
    em = pow(b2i(sig), e, n).to_bytes(k, "big")
    digest = SHA256_DER + hashlib.sha256(msg).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(digest) - 3) + b"\x00" + digest
    return secrets.compare_digest(em, expected)


def check_assertion(assertion: str, token_url: str) -> str:
    try:
        h64, c64, s64 = assertion.split(".")
        header, claims = json.loads(b64d(h64)), json.loads(b64d(c64))
    except Exception as exc:  # noqa: BLE001
        raise ApiError(401, "invalid_client", f"The client_assertion is malformed: {exc}") from None
    client = claims.get("iss")
    jwk = SERVICE_APPS.get(client)
    if jwk is None or claims.get("sub") != client:
        raise ApiError(401, "invalid_client", "The client_assertion iss/sub is not a known service app")
    msg, sig = f"{h64}.{c64}".encode(), b64d(s64)
    ok = verify_es256(jwk, msg, sig) if header.get("alg") == "ES256" else (
        verify_rs256(jwk, msg, sig) if header.get("alg") == "RS256" else False)
    if not ok or header.get("alg") != ("ES256" if jwk["kty"] == "EC" else "RS256"):
        raise ApiError(401, "invalid_client", "The client_assertion signature is invalid")
    now = time.time()
    if claims.get("aud") != token_url:
        raise ApiError(401, "invalid_client", f"The audience claim must be {token_url}")
    if not (isinstance(claims.get("exp"), int) and claims["exp"] > now and claims["exp"] - claims.get("iat", 0) <= 3600):
        raise ApiError(401, "invalid_client", "The client_assertion token is expired or has a bad lifetime")
    jti = claims.get("jti")
    with LOCK:
        if not jti or jti in SEEN_JTI:
            raise ApiError(401, "invalid_client", "The client_assertion jti was already used")
        SEEN_JTI.add(jti)
    return client


# ------------------------------------------------------------------------- routes


def paged(items: list, query: dict, default: int, maximum: int):
    raw = query.get("limit")
    if raw is not None:
        if not re.fullmatch(r"\d+", raw) or int(raw) < 1:
            raise bad_request("limit: must be a positive integer")
    limit = min(int(raw or default), maximum)
    after = query.get("after")
    start = 0
    if after:
        try:
            start = int(b64d(after).decode().removeprefix("c:"))
        except Exception:  # noqa: BLE001
            raise bad_request("after: invalid cursor") from None
    page = items[start : start + limit]
    nxt = start + limit if start + limit < len(items) else None
    return page, (base64.urlsafe_b64encode(f"c:{nxt}".encode()).decode().rstrip("=") if nxt is not None else None)


def find(items: list, key: str, value: str, kind: str):
    for x in items:
        if x.get(key) == value:
            return x
    raise ApiError(404, "E0000007", f"Not found: Resource not found: {value} ({kind})")


def find_user(ident: str) -> dict:
    for u in ORG["users"]:
        if ident in (u["id"], u["profile"]["login"], u["profile"]["login"].split("@")[0]):
            return u
    raise ApiError(404, "E0000007", f"Not found: Resource not found: {ident} (User)")


USER_ATTRS = ("id", "status", "created", "activated", "statusChanged", "lastUpdated", "lastLogin", "passwordChanged",
              "type.id", "profile.*")
GROUP_ATTRS = ("id", "type", "created", "lastUpdated", "lastMembershipUpdated", "profile.*")
DEVICE_ATTRS = ("id", "status", "created", "lastUpdated", "profile.*")
LOG_ATTRS = ("eventType", "uuid", "severity", "actor.*", "outcome.*", "client.*", "transaction.*", "target.*",
             "authenticationContext.*", "debugContext.*", "legacyEventType")


def r_users(q, m):
    items = ORG["users"]
    if q.get("search"):
        items = where(items, q["search"], USER_ATTRS)
    else:
        items = [u for u in items if u["status"] != "DEPROVISIONED"]
        items = where(items, q.get("filter"), ("id", "status", "lastUpdated", "profile.login", "profile.email",
                                               "profile.firstName", "profile.lastName", "type.id"))
        if q.get("q"):
            t = q["q"].lower()
            items = [u for u in items if any(str(u["profile"].get(k, "")).lower().startswith(t)
                                             for k in ("firstName", "lastName", "email", "login"))]
    return paged(items, q, 200, 200)


def r_user(q, m):
    return find_user(m[1]), None


def r_user_groups(q, m):
    uid = find_user(m[1])["id"]
    return [g for g in ORG["groups"] if uid in ORG["group_members"].get(g["id"], [])], None


def r_user_factors(q, m):
    return ORG["factors"].get(find_user(m[1])["id"], []), None


def r_user_roles(q, m):
    return ORG["user_roles"].get(find_user(m[1])["id"], []), None


def r_groups(q, m):
    items = where(ORG["groups"], q.get("search"), GROUP_ATTRS)
    if q.get("q"):
        items = [g for g in items if g["profile"]["name"].lower().startswith(q["q"].lower())]
    return paged(items, q, 10000, 10000)


def r_group_members(q, m):
    g = find(ORG["groups"], "id", m[1], "UserGroup")
    ids = ORG["group_members"].get(g["id"], [])
    return paged([u for u in ORG["users"] if u["id"] in ids], q, 1000, 1000)


def r_group_roles(q, m):
    find(ORG["groups"], "id", m[1], "UserGroup")
    return ORG["group_roles"].get(m[1], []), None


def r_group_rules(q, m):
    items = ORG["group_rules"]
    if q.get("search"):
        items = [r for r in items if q["search"].lower() in r["name"].lower()]
    return paged(items, q, 50, 200)


def r_apps(q, m):
    items = where(ORG["apps"], q.get("filter"), ("status", "name", "user.id", "group.id"))
    if q.get("q"):
        t = q["q"].lower()
        items = [a for a in items if a["name"].lower().startswith(t) or a["label"].lower().startswith(t)]
    return paged(items, q, 20, 200)


def r_app_users(q, m):
    find(ORG["apps"], "id", m[1], "AppInstance")
    return paged(ORG["app_users"].get(m[1], []), q, 50, 500)


def r_app_groups(q, m):
    find(ORG["apps"], "id", m[1], "AppInstance")
    return paged(ORG["app_groups"].get(m[1], []), q, 20, 200)


POLICY_TYPES = {"OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "IDP_DISCOVERY", "ACCESS_POLICY", "PROFILE_ENROLLMENT",
                "POST_AUTH_SESSION", "ENTITY_RISK"}


def r_policies(q, m):
    t = q.get("type")
    if t not in POLICY_TYPES:
        raise bad_request(f"type: must be one of {sorted(POLICY_TYPES)}")
    items = [p for p in ORG["policies"] if p["type"] == t]
    if q.get("status"):
        if q["status"] not in ("ACTIVE", "INACTIVE"):
            raise bad_request("status: must be ACTIVE or INACTIVE")
        items = [p for p in items if p["status"] == q["status"]]
    return paged(items, q, 20, 200)


def r_policy_rules(q, m):
    find(ORG["policies"], "id", m[1], "Policy")
    return ORG["policy_rules"].get(m[1], []), None


def r_auth_servers(q, m):
    items = ORG["authorization_servers"]
    if q.get("q"):
        items = [a for a in items if a["name"].lower().startswith(q["q"].lower())]
    return paged(items, q, 200, 200)


def r_assignees(q, m):
    page, nxt = paged([{"id": u, "orn": f"orn:okta:directory:acme:users:{u}"} for u in ORG["role_assignees"]], q, 100, 100)
    return {"value": page}, nxt


def r_devices(q, m):
    items = where(ORG["devices"], q.get("search"), DEVICE_ATTRS)
    out = []
    for d in items:
        d = {k: v for k, v in d.items() if k != "_embedded_users"}
        if q.get("expand") == "user":
            users = [u for u in ORG["users"] if u["id"] in next(x for x in ORG["devices"] if x["id"] == d["id"])["_embedded_users"]]
            d["_embedded"] = {"users": [{"created": d["created"], "managementStatus": "NOT_MANAGED", "user": u} for u in users]}
        out.append(d)
    if q.get("expand") not in (None, "user", "userSummary"):
        raise bad_request("expand: must be user or userSummary")
    return paged(out, q, 200, 200)


def r_zones(q, m):
    f = q.get("filter")
    if f and " or " in f:
        raise bad_request("filter: only a single expression is supported", "E0000031")
    return paged(where(ORG["zones"], f, ("id", "usage")), q, 20, 200)


def r_logs(q, m):
    now = dt.datetime.now(dt.timezone.utc)
    since = parse_time(q["since"]) if q.get("since") else now - dt.timedelta(days=7)
    until = parse_time(q["until"]) if q.get("until") else None
    if since is None or (q.get("until") and until is None):
        raise bad_request("since/until: must be ISO 8601 timestamps")
    if since < now - RETENTION:
        raise bad_request("since: must be within the 90-day retention period")
    if until is not None and until <= since:
        raise bad_request("until: must be after since")
    order = q.get("sortOrder", "ASCENDING")
    if order not in ("ASCENDING", "DESCENDING"):
        raise bad_request("sortOrder: must be ASCENDING or DESCENDING")
    items = [e for e in ORG["logs"] if parse_time(e["published"]) >= since and (until is None or parse_time(e["published"]) < until)]
    items = where(items, q.get("filter"), LOG_ATTRS)
    if q.get("q"):
        terms = q["q"].lower().split()
        items = [e for e in items if all(t in json.dumps(e).lower() for t in terms)]
    items.sort(key=lambda e: (e["published"], e["uuid"]), reverse=order == "DESCENDING")
    page, nxt = paged(items, q, 100, 1000)
    if nxt is None and until is None and order == "ASCENDING":
        nxt = base64.urlsafe_b64encode(f"c:{len(items)}".encode()).decode().rstrip("=")  # polling: never ends
    return page, nxt


ROUTES = [
    (r"/api/v1/users", r_users, {"q", "filter", "search", "limit", "after", "sortBy", "sortOrder"}, "okta.users.read"),
    (r"/api/v1/users/([^/]+)", r_user, set(), "okta.users.read"),
    (r"/api/v1/users/([^/]+)/groups", r_user_groups, set(), "okta.users.read"),
    (r"/api/v1/users/([^/]+)/factors", r_user_factors, set(), "okta.users.read"),
    (r"/api/v1/users/([^/]+)/roles", r_user_roles, {"expand"}, "okta.roles.read"),
    (r"/api/v1/groups", r_groups, {"q", "search", "filter", "limit", "after", "expand"}, "okta.groups.read"),
    (r"/api/v1/groups/rules", r_group_rules, {"limit", "after", "search", "expand"}, "okta.groups.read"),
    (r"/api/v1/groups/([^/]+)/users", r_group_members, {"limit", "after"}, "okta.groups.read"),
    (r"/api/v1/groups/([^/]+)/roles", r_group_roles, {"expand"}, "okta.roles.read"),
    (r"/api/v1/apps", r_apps, {"q", "filter", "limit", "after", "expand", "includeNonDeleted"}, "okta.apps.read"),
    (r"/api/v1/apps/([^/]+)/users", r_app_users, {"q", "limit", "after", "expand"}, "okta.apps.read"),
    (r"/api/v1/apps/([^/]+)/groups", r_app_groups, {"q", "limit", "after", "expand"}, "okta.apps.read"),
    (r"/api/v1/policies", r_policies, {"type", "status", "q", "limit", "after", "expand", "sortBy"}, "okta.policies.read"),
    (r"/api/v1/policies/([^/]+)/rules", r_policy_rules, {"limit"}, "okta.policies.read"),
    (r"/api/v1/authorizationServers", r_auth_servers, {"q", "limit", "after"}, "okta.authorizationServers.read"),
    (r"/api/v1/iam/assignees/users", r_assignees, {"limit", "after"}, "okta.roles.read"),
    (r"/api/v1/devices", r_devices, {"search", "limit", "after", "expand"}, "okta.devices.read"),
    (r"/api/v1/zones", r_zones, {"filter", "limit", "after"}, "okta.networkZones.read"),
    (r"/api/v1/logs", r_logs, {"since", "until", "filter", "q", "limit", "sortOrder", "after"}, "okta.logs.read"),
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        """Log to stderr only, so stdout carries nothing except the ``PORT:`` line."""
        sys.stderr.write("okta_mock: " + (format % args) + "\n")

    @property
    def origin(self) -> str:
        return f"http://{self.headers.get('Host', '127.0.0.1')}"

    def _send(self, status: int, body: object, headers: dict | None = None) -> None:
        payload = json.dumps(body).replace(FIXTURE_ORIGIN, self.origin).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        reset = str(int(time.time()) + 60)
        rl = {"X-Rate-Limit-Limit": "600", "X-Rate-Limit-Remaining": "598", "X-Rate-Limit-Reset": reset}
        rl.update(headers or {})
        for k, v in rl.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, e: ApiError) -> None:
        if e.code.startswith("E"):
            body = {"errorCode": e.code, "errorSummary": e.summary, "errorLink": e.code,
                    "errorId": secrets.token_hex(8), "errorCauses": []}
        else:
            body = {"error": e.code, "error_description": e.summary}
        self._send(e.status, body, e.headers)

    def _auth(self) -> tuple[str, set[str]]:
        h = self.headers.get("Authorization", "")
        if h == f"SSWS {API_TOKEN}":
            return "ssws", ALL_SCOPES
        if h.startswith("Bearer "):
            with LOCK:
                scopes = TOKENS.get(h[7:])
            if scopes is not None:
                return "bearer", scopes
        raise ApiError(401, "E0000011", "Invalid token provided")

    def do_POST(self) -> None:
        url = urlparse(self.path)
        try:
            if url.path != "/oauth2/v1/token":
                raise ApiError(404, "E0000022", "The endpoint does not support the provided HTTP method")
            length = int(self.headers.get("Content-Length", "0"))
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
            self._record("POST", url.path, {k: v for k, v in form.items() if k != "client_assertion"}, "client_assertion")
            if form.get("grant_type") != "client_credentials":
                raise ApiError(400, "unsupported_grant_type", "grant_type must be client_credentials")
            if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
                raise ApiError(400, "invalid_request", "client_assertion_type must be jwt-bearer")
            check_assertion(form.get("client_assertion", ""), f"{self.origin}/oauth2/v1/token")
            scopes = set(form.get("scope", "").split())
            if not scopes or not scopes <= ALL_SCOPES:
                raise ApiError(400, "invalid_scope", f"One or more scopes are not configured: {sorted(scopes - ALL_SCOPES)}")
            token = secrets.token_urlsafe(24)
            with LOCK:
                TOKENS[token] = scopes
            self._send(200, {"token_type": "Bearer", "expires_in": 3600, "access_token": token, "scope": " ".join(sorted(scopes))})
        except ApiError as e:
            self._error(e)

    def _record(self, method: str, path: str, query: dict, auth: str) -> None:
        with LOCK:
            REQUESTS.append({"seq": len(REQUESTS) + 1, "method": method, "path": path,
                             "query": json.dumps(query, sort_keys=True), "auth": auth})

    def do_GET(self) -> None:
        url = urlparse(self.path)
        raw = parse_qs(url.query, keep_blank_values=True)
        query = {k: v[-1] for k, v in raw.items()}
        if url.path == "/health":
            self._send(200, {"status": "ok"})
            return
        if url.path == "/__requests":
            with LOCK:
                rows = [r for r in REQUESTS if not query.get("path") or r["path"] == query["path"]]
            self._send(200, rows)
            return
        try:
            for pattern, fn, allowed, scope in ROUTES:
                m = re.fullmatch(pattern, url.path)
                if not m:
                    continue
                kind, scopes = self._auth()
                self._record("GET", url.path, query, kind)
                if scope not in scopes:
                    raise ApiError(403, "E0000006", f"You do not have permission to perform the requested action (needs {scope})")
                unknown = set(query) - allowed
                if unknown:
                    raise bad_request(f"unknown query parameter(s): {sorted(unknown)}")
                for key, once_status in (("/api/v1/groups/rules", 429), ("/api/v1/zones", 503)):
                    if url.path == key:
                        with LOCK:
                            first = key not in ONCE
                            ONCE.add(key)
                        if first and once_status == 429:
                            raise ApiError(429, "E0000047", "API call exceeded rate limit due to too many requests.",
                                           {"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": str(int(time.time()) + 1)})
                        if first:
                            raise ApiError(503, "E0000009", "Internal Server Error")
                body, nxt = fn(query, [m[0], *(unquote(g) for g in m.groups())])
                headers = {}
                if nxt is not None:
                    params = {**query, "after": nxt}
                    headers["Link"] = f'<{self.origin}{self.path}>; rel="self", <{self.origin}{url.path}?{urlencode(params)}>; rel="next"'
                self._send(200, body, headers)
                return
            raise ApiError(404, "E0000022", f"The endpoint does not exist: {url.path}")
        except ApiError as e:
            self._error(e)


def main() -> None:
    """Serve until interrupted, printing ``PORT:<n>`` once bound."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--port", type=int, default=0, help="port to bind (default: any free port)")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"PORT:{server.server_address[1]}", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()
