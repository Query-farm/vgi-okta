/**
 * Turn DuckDB's pushed-down WHERE predicates into Okta query parameters.
 *
 * Every table function here sets `autoApplyFilters: true`, so the SDK re-applies
 * every pushed predicate to each batch exactly. Translation therefore only has to
 * NARROW the upstream request without ever dropping a matching row: predicates we
 * cannot express are simply not sent, and anything Okta matches more loosely (for
 * example case-insensitive profile matching) is tightened again by the SDK.
 *
 * Only top-level conjuncts are translated (a predicate under OR/NOT is left to the
 * SDK), so the generated expression is always implied by the SQL filter.
 */

import type { PushdownFilters } from "@query-farm/vgi";

type Expr = PushdownFilters["filters"][number];

/** One translatable constraint on a column. */
export type Constraint =
  | { kind: "cmp"; column: string; op: "eq" | "gt" | "ge" | "lt" | "le"; value: unknown }
  | { kind: "in"; column: string; values: unknown[] }
  | { kind: "prefix"; column: string; value: string };

const FLIP: Record<string, "eq" | "gt" | "ge" | "lt" | "le"> = { eq: "eq", gt: "lt", ge: "le", lt: "gt", le: "ge" };

function unwrap(e: Expr): Expr {
  return e.node === "cast" ? unwrap(e.expression) : e;
}

function one(e: Expr, out: Constraint[]): void {
  // A bare boolean column (`WHERE account_enabled`) and its negation.
  if (e.node === "column_ref") {
    out.push({ kind: "cmp", column: e.columnName, op: "eq", value: true });
    return;
  }
  if (e.node === "not" && unwrap(e.expression).node === "column_ref") {
    const c = unwrap(e.expression) as Extract<Expr, { node: "column_ref" }>;
    out.push({ kind: "cmp", column: c.columnName, op: "eq", value: false });
    return;
  }
  if (e.node === "and") {
    for (const c of e.children) one(c, out);
    return;
  }
  if (e.node === "comparison" && e.op in FLIP) {
    const [l, r] = [unwrap(e.left), unwrap(e.right)];
    if (l.node === "column_ref" && r.node === "literal" && r.value != null) {
      out.push({ kind: "cmp", column: l.columnName, op: e.op as "eq", value: r.value });
    } else if (r.node === "column_ref" && l.node === "literal" && l.value != null) {
      out.push({ kind: "cmp", column: r.columnName, op: FLIP[e.op] ?? "eq", value: l.value });
    }
    return;
  }
  if (e.node === "in" && !e.negated && e.set.kind === "literal") {
    const col = unwrap(e.expression);
    const values = e.set.values.filter((v) => v != null);
    if (col.node === "column_ref" && values.length > 0 && values.length === e.set.values.length) {
      out.push({ kind: "in", column: col.columnName, values });
    }
    return;
  }
  if (e.node === "call" && e.function === "starts_with" && e.arguments.length === 2) {
    const [c, v] = [unwrap(e.arguments[0] as Expr), unwrap(e.arguments[1] as Expr)];
    if (c.node === "column_ref" && v.node === "literal" && typeof v.value === "string") {
      out.push({ kind: "prefix", column: c.columnName, value: v.value });
    }
  }
}

/** The top-level, translatable constraints of a scan's pushed filters. */
export function constraintsOf(filters: PushdownFilters | undefined): Constraint[] {
  const out: Constraint[] = [];
  for (const f of filters?.filters ?? []) one(f, out);
  return [...out, ...prefixesFromRanges(out)];
}

/** The string after every string starting with `p` (DuckDB's prefix-range upper bound). */
function prefixSuccessor(p: string): string | undefined {
  if (!p) return undefined;
  const last = p.codePointAt(p.length - 1);
  return last === undefined ? undefined : p.slice(0, -1) + String.fromCodePoint(last + 1);
}

/**
 * DuckDB rewrites `starts_with(col, 'ad')` and `col LIKE 'ad%'` into the range
 * `col >= 'ad' AND col < 'ae'`. Recognise that pair and add a prefix constraint so
 * endpoints with `sw` can push it (the range itself is still re-applied exactly).
 */
function prefixesFromRanges(cs: Constraint[]): Constraint[] {
  const out: Constraint[] = [];
  for (const lo of cs) {
    if (lo.kind !== "cmp" || lo.op !== "ge" || typeof lo.value !== "string") continue;
    const hi = prefixSuccessor(lo.value);
    if (cs.some((c) => c.kind === "cmp" && c.column === lo.column && c.op === "lt" && c.value === hi)) {
      out.push({ kind: "prefix", column: lo.column, value: lo.value });
    }
  }
  return out;
}

/** A pushed literal for a TIMESTAMPTZ column as epoch milliseconds (µs bigint, ms number, Date, ISO). */
export function toEpochMs(v: unknown): number | undefined {
  if (typeof v === "bigint") return Number(v / 1000n);
  if (typeof v === "number") return v;
  if (v instanceof Date) return v.getTime();
  if (typeof v === "string") {
    const t = Date.parse(v);
    return Number.isNaN(t) ? undefined : t;
  }
  return undefined;
}

/** Okta's timestamp literal form: ISO 8601 with milliseconds and Z. */
export function oktaTime(ms: number): string {
  return new Date(ms).toISOString();
}

/** Quote a string for an Okta filter/search expression (double quotes, backslash escapes). */
export function quote(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** How one SQL column maps onto an Okta expression attribute. */
export interface AttrMap {
  /** Okta attribute path, e.g. `profile.login`. */
  attr: string;
  kind: "string" | "time" | "bool";
  /** Allow `sw` (starts_with) — only where the endpoint supports it. */
  prefix?: boolean;
  /** Allow range operators (gt/ge/lt/le) — time attributes. */
  range?: boolean;
  /** Map the SQL value onto Okta's (e.g. account_enabled → status). */
  value?: (v: unknown) => string | undefined;
}

/**
 * Build an Okta `search` / `filter` expression (SCIM-like: `attr op "value"` joined by
 * `and`; IN lists become a parenthesised `or`) from the translatable constraints.
 * Returns the parts so callers can AND them with a user-supplied expression.
 */
export function buildExpression(constraints: Constraint[], attrs: Record<string, AttrMap>): string[] {
  const parts: string[] = [];
  const lit = (m: AttrMap, v: unknown): string | undefined => {
    if (m.value) {
      const mapped = m.value(v);
      return mapped === undefined ? undefined : quote(mapped);
    }
    if (m.kind === "time") {
      const ms = toEpochMs(v);
      return ms === undefined ? undefined : quote(oktaTime(ms));
    }
    if (m.kind === "bool") return typeof v === "boolean" ? String(v) : undefined;
    return typeof v === "string" ? quote(v) : undefined;
  };
  for (const c of constraints) {
    const m = attrs[c.column];
    if (!m) continue;
    if (c.kind === "cmp") {
      if (c.op !== "eq" && !m.range) continue;
      // Okta has no "le"/"ge" for some attributes; widen strict-vs-inclusive safely is
      // not needed: gt/ge/lt/le are all supported on timestamp attributes.
      const v = lit(m, c.value);
      if (v !== undefined) parts.push(`${m.attr} ${c.op} ${v}`);
    } else if (c.kind === "in") {
      const vs = c.values.map((v) => lit(m, v));
      if (vs.some((v) => v === undefined) || vs.length > 50) continue;
      const uniq = [...new Set(vs as string[])];
      parts.push(
        uniq.length === 1 ? `${m.attr} eq ${uniq[0]}` : `(${uniq.map((v) => `${m.attr} eq ${v}`).join(" or ")})`,
      );
    } else if (c.kind === "prefix" && m.prefix && c.value !== "") {
      parts.push(`${m.attr} sw ${quote(c.value)}`);
    }
  }
  return parts;
}

/** AND together generated parts and an optional caller-supplied expression. */
export function andJoin(parts: string[], userExpr?: string | null): string | undefined {
  const all = [...parts];
  if (userExpr?.trim()) all.unshift(parts.length ? `(${userExpr.trim()})` : userExpr.trim());
  return all.length ? all.join(" and ") : undefined;
}

/** The tightest [lower, upper] epoch-ms bounds the constraints put on a time column. */
export function timeBounds(constraints: Constraint[], column: string): { lower?: number; upper?: number } {
  let lower: number | undefined;
  let upper: number | undefined;
  for (const c of constraints) {
    if (c.column !== column || c.kind !== "cmp") continue;
    const ms = toEpochMs(c.value);
    if (ms === undefined) continue;
    if (c.op === "gt" || c.op === "ge" || c.op === "eq") lower = lower === undefined ? ms : Math.max(lower, ms);
    if (c.op === "lt" || c.op === "le" || c.op === "eq") {
      // Okta's `until` is exclusive; an inclusive bound widens by 1 ms.
      const u = c.op === "lt" ? ms : ms + 1;
      upper = upper === undefined ? u : Math.min(upper, u);
    }
  }
  return { lower, upper };
}

/** Equality / IN values pushed for a column (as strings), or undefined if unconstrained. */
export function eqValues(constraints: Constraint[], column: string): string[] | undefined {
  let set: string[] | undefined;
  for (const c of constraints) {
    if (c.column !== column) continue;
    let vs: string[] | undefined;
    if (c.kind === "cmp" && c.op === "eq" && typeof c.value === "string") vs = [c.value];
    else if (c.kind === "in" && c.values.every((v) => typeof v === "string")) vs = c.values as string[];
    if (!vs) continue;
    set = set ? set.filter((v) => vs.includes(v)) : [...new Set(vs)];
  }
  return set;
}
