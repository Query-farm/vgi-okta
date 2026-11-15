// Unit tests. The SQL-level tests live in test/sql and run through DuckDB.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Arguments, VgiClient } from "@query-farm/vgi";
import { subprocessConnect } from "@query-farm/vgi-rpc";
import {
  assertSameOrigin,
  clientAssertion,
  configFromSecrets,
  normalizeOrgUrl,
  type OktaConfig,
  oktaGet,
  parseLinkHeader,
  resetDelayMs,
} from "../src/okta/client.ts";
import { andJoin, buildExpression, type Constraint, quote, timeBounds } from "../src/okta/pushdown.ts";
import { logWindow, RETENTION_DAYS } from "../src/okta/resources.ts";
import { asTime } from "../src/okta/table.ts";

const ROOT = join(import.meta.dir, "..");
const DAY = 86_400_000;

test("parseLinkHeader: Okta's self + next links", () => {
  const h =
    '<https://acme.okta.com/api/v1/users?limit=2>; rel="self", <https://acme.okta.com/api/v1/users?after=00u2&limit=2>; rel="next"';
  expect(parseLinkHeader(h)).toEqual({
    self: "https://acme.okta.com/api/v1/users?limit=2",
    next: "https://acme.okta.com/api/v1/users?after=00u2&limit=2",
  });
  expect(parseLinkHeader(null)).toEqual({});
});

test("org_url: https required except for loopback fixtures; trailing slash dropped", () => {
  expect(normalizeOrgUrl("https://acme.okta.com/")).toBe("https://acme.okta.com");
  expect(normalizeOrgUrl("http://127.0.0.1:8080")).toBe("http://127.0.0.1:8080");
  expect(() => normalizeOrgUrl("http://acme.okta.com")).toThrow(/https/);
  expect(() => normalizeOrgUrl("not a url")).toThrow(/not a URL/);
});

test("configFromSecrets: needs org_url and a credential", () => {
  expect(() => configFromSecrets({})).toThrow(/no okta secret/);
  expect(() => configFromSecrets({ s: { type: "okta", org_url: "https://a.okta.com" } })).toThrow(/API_TOKEN/);
  const cfg = configFromSecrets({ s: { type: "okta", org_url: "https://a.okta.com", api_token: "t" } });
  expect(cfg.apiToken).toBe("t");
  expect(cfg.scopes).toContain("okta.logs.read");
});

test("assertSameOrigin: never sends the credential to another host", () => {
  const cfg: OktaConfig = { orgUrl: "https://acme.okta.com", apiToken: "t", scopes: "" };
  expect(() => assertSameOrigin(cfg, "https://acme.okta.com/api/v1/users?after=x")).not.toThrow();
  expect(() => assertSameOrigin(cfg, "https://evil.example.com/api/v1/users")).toThrow(/refusing/);
});

test("clientAssertion: RS256 and ES256 signatures verify; claims target the token endpoint", () => {
  const tokenUrl = "https://acme.okta.com/oauth2/v1/token";
  const jwks = JSON.parse(readFileSync(join(ROOT, "test/fixtures/service-app-public-jwks.json"), "utf8"));
  for (const [kind, file, alg] of [
    ["rsa", "service-app-rsa.pem", "RS256"],
    ["ec", "service-app-ec.pem", "ES256"],
  ] as const) {
    const pem = readFileSync(join(ROOT, "test/fixtures", file), "utf8");
    const jwt = clientAssertion(
      { orgUrl: "https://acme.okta.com", clientId: "0oa1", privateKey: pem, keyId: "k1", scopes: "" },
      tokenUrl,
      1000,
    );
    const [h, c, sig] = jwt.split(".") as [string, string, string];
    const header = JSON.parse(Buffer.from(h, "base64url").toString());
    const claims = JSON.parse(Buffer.from(c, "base64url").toString());
    expect(header).toEqual({ alg, typ: "JWT", kid: "k1" });
    expect(claims).toMatchObject({ aud: tokenUrl, iss: "0oa1", sub: "0oa1", iat: 1000, exp: 1300 });
    const key = createPublicKey({ key: jwks[kind], format: "jwk" });
    const ok = verify(
      "sha256",
      Buffer.from(`${h}.${c}`),
      kind === "ec" ? { key, dsaEncoding: "ieee-p1363" } : key,
      Buffer.from(sig, "base64url"),
    );
    expect(ok).toBe(true);
  }
  expect(() =>
    clientAssertion({ orgUrl: "https://a", clientId: "x", privateKey: "nope", scopes: "" }, tokenUrl),
  ).toThrow(/PEM or JWK/);
});

test("buildExpression: eq / IN / prefix / ranges, quoting, and unmapped columns skipped", () => {
  const cs: Constraint[] = [
    { kind: "cmp", column: "status", op: "eq", value: "ACTIVE" },
    { kind: "in", column: "department", values: ["R&D", 'Say "hi"'] },
    { kind: "prefix", column: "login", value: "ad" },
    { kind: "cmp", column: "last_updated", op: "gt", value: 1_767_225_600_000_000n }, // µs
    { kind: "cmp", column: "login", op: "gt", value: "m" }, // no range on strings: skipped
    { kind: "cmp", column: "nope", op: "eq", value: "x" },
  ];
  const parts = buildExpression(cs, {
    status: { attr: "status", kind: "string" },
    department: { attr: "profile.department", kind: "string" },
    login: { attr: "profile.login", kind: "string", prefix: true },
    last_updated: { attr: "lastUpdated", kind: "time", range: true },
  });
  expect(parts).toEqual([
    'status eq "ACTIVE"',
    '(profile.department eq "R&D" or profile.department eq "Say \\"hi\\"")',
    'profile.login sw "ad"',
    'lastUpdated gt "2026-01-01T00:00:00.000Z"',
  ]);
  expect(andJoin(parts.slice(0, 1), 'profile.x eq "1"')).toBe('(profile.x eq "1") and status eq "ACTIVE"');
  expect(andJoin([], null)).toBeUndefined();
  expect(quote('a\\b"c')).toBe('"a\\\\b\\"c"');
});

test("timeBounds / logWindow: since/until from published, clamped to retention and scan start", () => {
  const anchor = Date.UTC(2026, 10, 15);
  const cs: Constraint[] = [
    { kind: "cmp", column: "published", op: "ge", value: BigInt(anchor - 2 * DAY) * 1000n },
    { kind: "cmp", column: "published", op: "le", value: BigInt(anchor - DAY) * 1000n },
  ];
  expect(timeBounds(cs, "published")).toEqual({ lower: anchor - 2 * DAY, upper: anchor - DAY + 1 });
  expect(logWindow(cs, 7, anchor)).toEqual({ since: anchor - 2 * DAY, until: anchor - DAY + 1 });
  // No bounds: lookback_days before the anchor, until = anchor (always a bounded request).
  expect(logWindow([], 7, anchor)).toEqual({ since: anchor - 7 * DAY, until: anchor });
  // Older than retention: clamped.
  const old: Constraint[] = [{ kind: "cmp", column: "published", op: "gt", value: BigInt(anchor - 400 * DAY) * 1000n }];
  expect(logWindow(old, 7, anchor)?.since).toBe(anchor - RETENTION_DAYS * DAY + 60_000);
  // Entirely outside the window: no request at all.
  const empty: Constraint[] = [
    { kind: "cmp", column: "published", op: "lt", value: BigInt(anchor - 200 * DAY) * 1000n },
  ];
  expect(logWindow(empty, 7, anchor)).toBeNull();
});

test("asTime: Okta ISO timestamps to TIMESTAMPTZ microseconds", () => {
  expect(asTime("2026-01-01T00:00:00.000Z")).toBe(1_767_225_600_000_000n);
  expect(asTime(null)).toBeNull();
  expect(asTime("garbage")).toBeNull();
});

test("resetDelayMs: X-Rate-Limit-Reset (epoch seconds) then Retry-After", () => {
  const now = 1_000_000;
  expect(resetDelayMs(new Headers({ "X-Rate-Limit-Reset": "1002" }), now)).toBe(2250);
  expect(resetDelayMs(new Headers({ "Retry-After": "3" }), now)).toBe(3000);
  expect(resetDelayMs(new Headers(), now)).toBeUndefined();
});

describe("oktaGet against a local server", () => {
  let server: ReturnType<typeof Bun.serve>;
  let hits: { path: string; auth: string | null }[] = [];
  let mode = "ok";

  beforeAll(() => {
    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);
        hits.push({ path: url.pathname + url.search, auth: req.headers.get("Authorization") });
        const reset = String(Math.floor(Date.now() / 1000));
        if (mode === "429-once" && hits.length === 1) {
          return new Response(JSON.stringify({ errorCode: "E0000047", errorSummary: "rate limit" }), {
            status: 429,
            headers: { "X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": reset },
          });
        }
        if (mode === "404") {
          return Response.json(
            { errorCode: "E0000007", errorSummary: "Not found: Resource not found: x (User)" },
            { status: 404 },
          );
        }
        const next = url.searchParams.get("after") ? null : `<${url.origin}/api/v1/x?after=2>; rel="next"`;
        return Response.json([{ id: url.searchParams.get("after") ?? "1" }], {
          headers: { ...(next ? { Link: next } : {}), "X-Rate-Limit-Remaining": "100", "X-Rate-Limit-Reset": reset },
        });
      },
    });
  });
  afterAll(() => server.stop(true));

  const cfg = (): OktaConfig => ({ orgUrl: `http://127.0.0.1:${server.port}`, apiToken: "tok", scopes: "" });

  test("SSWS header, query encoding and the next link", async () => {
    hits = [];
    mode = "ok";
    const page = await oktaGet(cfg(), "/api/v1/x", { search: 'a eq "b"', skip: undefined });
    expect(hits[0]).toEqual({ path: "/api/v1/x?search=a+eq+%22b%22", auth: "SSWS tok" });
    expect(page.next).toBe(`http://127.0.0.1:${server.port}/api/v1/x?after=2`);
    const second = await oktaGet(cfg(), page.next as string);
    expect(second.body).toEqual([{ id: "2" }]);
    expect(second.next).toBeNull();
  });

  test("429 waits for the reset, then succeeds", async () => {
    hits = [];
    mode = "429-once";
    const page = await oktaGet(cfg(), "/api/v1/x");
    expect(hits.length).toBe(2);
    expect(page.body).toEqual([{ id: "1" }]);
  });

  test("4xx is not retried and carries the Okta error summary", async () => {
    hits = [];
    mode = "404";
    await expect(oktaGet(cfg(), "/api/v1/users/x")).rejects.toThrow(/HTTP 404: E0000007 - Not found/);
    expect(hits.length).toBe(1);
  });
});

describe("the worker subprocess", () => {
  let client: VgiClient;

  beforeAll(() => {
    client = new VgiClient(subprocessConnect([process.execPath, "run", join(ROOT, "src", "worker.ts")]));
  });
  afterAll(() => client?.close());

  // Fixture-backed results are covered end to end through DuckDB in test/sql (all
  // transports); here the worker must fail clearly when no okta secret is attached.
  test("a scan without an okta secret explains how to create one", async () => {
    const run = async () => {
      for await (const _ of client.tableFunctionRows({
        functionName: "users",
        arguments: new Arguments([], new Map()),
        int64: "bigint",
      })) {
        // no rows expected
      }
    };
    await expect(run()).rejects.toThrow(/CREATE SECRET \(TYPE okta/);
  });
});
