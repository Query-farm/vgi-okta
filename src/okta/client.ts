/**
 * Okta Management API client: authentication, rate limits and Link-header paging.
 *
 * - **Auth.** An `okta` DuckDB secret carries the org URL plus either an SSWS API
 *   token (`Authorization: SSWS <token>`) or an OAuth 2.0 service app (client id +
 *   private key). The service-app path signs a `private_key_jwt` client assertion
 *   with node:crypto (RS256/ES256), exchanges it at `<org>/oauth2/v1/token` for a
 *   scoped access token, and caches the token in memory until shortly before it
 *   expires. Credentials never enter table-function state.
 * - **Rate limits.** Okta answers every call with `X-Rate-Limit-Limit / -Remaining /
 *   -Reset` (reset = epoch seconds). A 429 waits until the reset (bounded); when the
 *   bucket is about to run dry the client pauses before the next call instead of
 *   burning a 429. 5xx and network errors retry with exponential backoff.
 * - **Paging.** The next page is the `rel="next"` Link header. Callers keep that URL
 *   in their state (the cursor), and `assertSameOrigin` refuses to send the token to
 *   a host other than the configured org.
 */

import { createHash, createPrivateKey, randomUUID, sign } from "node:crypto";
import { secretOfType } from "@query-farm/vgi";
import { log } from "../log.ts";
import { VERSION } from "../meta.ts";

export const SECRET_TYPE = "okta";
export const TIMEOUT_MS = 30_000;
export const MAX_ATTEMPTS = 5;
/** Longest single wait for a rate-limit reset; Okta buckets reset every minute. */
export const MAX_RATE_WAIT_MS = 65_000;
const USER_AGENT = `vgi-okta-worker/${VERSION}`;

/** Read-only scopes requested for a service app when the secret names none. */
export const DEFAULT_SCOPES = [
  "okta.users.read",
  "okta.groups.read",
  "okta.apps.read",
  "okta.logs.read",
  "okta.policies.read",
  "okta.authorizationServers.read",
  "okta.roles.read",
  "okta.devices.read",
  "okta.networkZones.read",
].join(" ");

export class OktaError extends Error {}

export interface OktaConfig {
  orgUrl: string;
  apiToken?: string;
  clientId?: string;
  privateKey?: string;
  keyId?: string;
  scopes: string;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/** Normalize and check an org URL: https, or http only for a loopback fixture server. */
export function normalizeOrgUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new OktaError(`okta secret: org_url '${raw}' is not a URL (expected e.g. https://acme.okta.com)`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw new OktaError("okta secret: org_url must use https:// (http:// is accepted only for 127.0.0.1/localhost)");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v : undefined;
}

/** Build the client config from the `okta` secret DuckDB resolved for this call. */
export function configFromSecrets(secrets: Record<string, Record<string, unknown>>): OktaConfig {
  const s = secretOfType(secrets as never, SECRET_TYPE) as Record<string, unknown> | undefined;
  if (!s) {
    throw new OktaError(
      "no okta secret: run CREATE SECRET (TYPE okta, ORG_URL 'https://<org>.okta.com', API_TOKEN '<ssws token>') " +
        "or use CLIENT_ID + PRIVATE_KEY for an OAuth 2.0 service app",
    );
  }
  const orgRaw = str(s.org_url);
  if (!orgRaw) throw new OktaError("okta secret: org_url is required (e.g. https://acme.okta.com)");
  const cfg: OktaConfig = {
    orgUrl: normalizeOrgUrl(orgRaw),
    apiToken: str(s.api_token),
    clientId: str(s.client_id),
    privateKey: str(s.private_key),
    keyId: str(s.key_id),
    scopes: str(s.scopes) ?? DEFAULT_SCOPES,
  };
  if (!cfg.apiToken && !(cfg.clientId && cfg.privateKey)) {
    throw new OktaError("okta secret: set API_TOKEN, or both CLIENT_ID and PRIVATE_KEY (OAuth 2.0 service app)");
  }
  return cfg;
}

/** Refuse to follow a pagination link (and send the credential) off the org's origin. */
export function assertSameOrigin(cfg: OktaConfig, url: string): void {
  if (new URL(url).origin !== new URL(cfg.orgUrl).origin) {
    throw new OktaError(`refusing to follow a link to ${new URL(url).origin}: it is not the configured Okta org`);
  }
}

/** Parse an RFC 8288 Link header into rel → URL. */
export function parseLinkHeader(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(/,(?=\s*<)/)) {
    const m = part.match(/<([^>]+)>\s*;(.*)/);
    if (!m) continue;
    const rel = m[2]?.match(/rel="?([^";]+)"?/);
    if (rel?.[1] && m[1]) for (const r of rel[1].trim().split(/\s+/)) out[r] = m[1];
  }
  return out;
}

const b64url = (buf: Buffer | string) => Buffer.from(buf).toString("base64url");

/** Sign the `private_key_jwt` client assertion for the org token endpoint. */
export function clientAssertion(cfg: OktaConfig, tokenUrl: string, nowSeconds = Math.floor(Date.now() / 1000)): string {
  if (!cfg.clientId || !cfg.privateKey) throw new OktaError("okta secret: client_id and private_key are required");
  let key: ReturnType<typeof createPrivateKey>;
  try {
    const pem = cfg.privateKey.includes("\\n") ? cfg.privateKey.replace(/\\n/g, "\n") : cfg.privateKey;
    key = pem.trim().startsWith("{")
      ? createPrivateKey({ key: JSON.parse(pem), format: "jwk" })
      : createPrivateKey({ key: pem, format: "pem" });
  } catch (err) {
    throw new OktaError(`okta secret: private_key is not a PEM or JWK private key (${(err as Error).message})`);
  }
  const ec = key.asymmetricKeyType === "ec";
  if (!ec && key.asymmetricKeyType !== "rsa") {
    throw new OktaError(`okta secret: private_key must be RSA or EC P-256 (got ${key.asymmetricKeyType})`);
  }
  const header: Record<string, string> = { alg: ec ? "ES256" : "RS256", typ: "JWT" };
  if (cfg.keyId) header.kid = cfg.keyId;
  const claims = {
    aud: tokenUrl,
    iss: cfg.clientId,
    sub: cfg.clientId,
    iat: nowSeconds,
    exp: nowSeconds + 300,
    jti: randomUUID(),
  };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const sig = sign("sha256", Buffer.from(input), ec ? { key, dsaEncoding: "ieee-p1363" } : key);
  return `${input}.${b64url(sig)}`;
}

interface CachedToken {
  token: string;
  expiresAt: number;
}
const tokenCache = new Map<string, CachedToken>();

function cacheKey(cfg: OktaConfig): string {
  return createHash("sha256")
    .update([cfg.orgUrl, cfg.clientId, cfg.privateKey, cfg.keyId, cfg.scopes].join("\u0000"))
    .digest("hex");
}

/** Forget cached service-app tokens (tests). */
export function clearTokenCache(): void {
  tokenCache.clear();
}

/** Exchange a signed client assertion for an access token (cached until near expiry). */
async function accessToken(cfg: OktaConfig): Promise<string> {
  const key = cacheKey(cfg);
  const hit = tokenCache.get(key);
  if (hit && hit.expiresAt > Date.now() + 60_000) return hit.token;
  const tokenUrl = `${cfg.orgUrl}/oauth2/v1/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    scope: cfg.scopes,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: clientAssertion(cfg, tokenUrl),
  });
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": USER_AGENT,
    },
    body,
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const text = await res.text();
  if (!res.ok) {
    let detail = text.slice(0, 300);
    try {
      const j = JSON.parse(text) as { error?: string; error_description?: string };
      detail = `${j.error ?? ""}: ${j.error_description ?? ""}`;
    } catch {}
    throw new OktaError(`Okta token request failed with HTTP ${res.status} (${detail})`);
  }
  const j = JSON.parse(text) as { access_token?: string; expires_in?: number; token_type?: string };
  if (!j.access_token) throw new OktaError("Okta token response had no access_token");
  if (j.token_type && j.token_type.toLowerCase() === "dpop") {
    throw new OktaError("this Okta service app requires DPoP-bound tokens; disable 'Require DPoP' for the app");
  }
  tokenCache.set(key, { token: j.access_token, expiresAt: Date.now() + (j.expires_in ?? 3600) * 1000 });
  return j.access_token;
}

async function authHeader(cfg: OktaConfig): Promise<string> {
  if (cfg.apiToken) return `SSWS ${cfg.apiToken}`;
  return `Bearer ${await accessToken(cfg)}`;
}

/** Last rate-limit reading per org (module-level: one worker process, many scans). */
const buckets = new Map<string, { remaining: number; resetMs: number }>();

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** How long to wait for a rate-limit reset, from X-Rate-Limit-Reset (epoch seconds). */
export function resetDelayMs(headers: Headers, now = Date.now()): number | undefined {
  const reset = headers.get("X-Rate-Limit-Reset");
  if (reset && /^\d+$/.test(reset)) return Math.max(0, Number(reset) * 1000 - now) + 250;
  const retry = headers.get("Retry-After");
  if (retry && /^\d+$/.test(retry)) return Number(retry) * 1000;
  return undefined;
}

export interface OktaPage {
  body: unknown;
  next: string | null;
}

/**
 * GET one Okta resource page. `pathOrUrl` is either an API path (`/api/v1/users`) plus
 * `query`, or an absolute next-link URL from a previous page.
 */
export async function oktaGet(
  cfg: OktaConfig,
  pathOrUrl: string,
  query?: Record<string, string | undefined>,
): Promise<OktaPage> {
  let url: string;
  if (/^https?:\/\//.test(pathOrUrl)) {
    url = pathOrUrl;
  } else {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== "") qs.set(k, v);
    const q = qs.toString();
    url = `${cfg.orgUrl}${pathOrUrl}${q ? `?${q}` : ""}`;
  }
  assertSameOrigin(cfg, url);
  const bucketKey = new URL(cfg.orgUrl).origin;

  for (let attempt = 1; ; attempt++) {
    const bucket = buckets.get(bucketKey);
    if (bucket && bucket.remaining <= 1 && bucket.resetMs > Date.now()) {
      const wait = Math.min(bucket.resetMs - Date.now() + 250, MAX_RATE_WAIT_MS);
      log.info(`okta: rate-limit bucket nearly empty; waiting ${wait} ms for reset`);
      await sleep(wait);
    }
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { Accept: "application/json", Authorization: await authHeader(cfg), "User-Agent": USER_AGENT },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      if (err instanceof OktaError) throw err;
      if (attempt >= MAX_ATTEMPTS) throw new OktaError(`GET ${redact(url)} failed: ${(err as Error).message}`);
      await sleep(250 * 2 ** attempt);
      continue;
    }
    const remaining = res.headers.get("X-Rate-Limit-Remaining");
    const reset = res.headers.get("X-Rate-Limit-Reset");
    if (remaining && reset && /^\d+$/.test(remaining) && /^\d+$/.test(reset)) {
      buckets.set(bucketKey, { remaining: Number(remaining), resetMs: Number(reset) * 1000 });
    }
    if (res.ok) {
      const text = await res.text();
      const body = text ? JSON.parse(text) : null;
      return { body, next: parseLinkHeader(res.headers.get("Link")).next ?? null };
    }
    if (res.status === 401 && !cfg.apiToken) tokenCache.delete(cacheKey(cfg));
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= MAX_ATTEMPTS) {
      throw new OktaError(`GET ${redact(url)} failed with HTTP ${res.status}: ${await errorSummary(res)}`);
    }
    await res.body?.cancel();
    const delay =
      res.status === 429 ? Math.min(resetDelayMs(res.headers) ?? 1000 * attempt, MAX_RATE_WAIT_MS) : 250 * 2 ** attempt;
    log.debug(`okta: HTTP ${res.status} for ${redact(url)}; retry ${attempt} in ${delay} ms`);
    await sleep(delay);
  }
}

/** Okta errors are `{errorCode, errorSummary, errorCauses}`; keep the message short. */
async function errorSummary(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const j = JSON.parse(text) as {
      errorCode?: string;
      errorSummary?: string;
      errorCauses?: { errorSummary?: string }[];
    };
    const causes = (j.errorCauses ?? []).map((c) => c.errorSummary).filter(Boolean);
    return [j.errorCode, j.errorSummary, ...causes].filter(Boolean).join(" - ") || text.slice(0, 300);
  } catch {
    return text.slice(0, 300);
  }
}

/** Show the path + query of a URL in errors (no credentials are ever in a URL). */
function redact(url: string): string {
  const u = new URL(url);
  return `${u.pathname}${u.search}`;
}
