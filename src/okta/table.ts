/**
 * One factory for every Okta list endpoint.
 *
 * A spec names the columns (with a JSON extractor each), how arguments and pushed
 * filters become the first request of each phase, and optional row expansion. The
 * factory turns that into a VGI table function that:
 *
 * - streams one Okta page per Arrow batch;
 * - keeps its cursor (`phase` + the `rel="next"` URL) in serializable state, so a
 *   scan resumes on any process over HTTP and survives rate-limit pauses;
 * - reads the `okta` secret on every call and never stores it in state;
 * - pushes filters down (narrowing only) and lets the SDK re-apply them exactly.
 */

import {
  batchFromColumns,
  bool,
  constraintRecord,
  defineTableFunction,
  field,
  float64,
  formatPushedFilters,
  int32,
  list,
  schema,
  struct,
  type TableDescriptor,
  timestampMicros,
  utf8,
  type VgiDataType,
  type VgiFunction,
} from "@query-farm/vgi";
import { log } from "../log.ts";
import { type Category, column, objectTags } from "../meta.ts";
import { configFromSecrets, type OktaConfig, OktaError, oktaGet, SECRET_TYPE } from "./client.ts";
import { type Constraint, constraintsOf, eqValues } from "./pushdown.ts";

// ------------------------------------------------------------------ column helpers

export interface Col {
  name: string;
  type: VgiDataType;
  /** DuckDB spelling for vgi.result_columns_schema. */
  sqlType: string;
  doc: string;
  nullable?: boolean;
  get: (row: Row) => unknown;
}

// biome-ignore lint/suspicious/noExplicitAny: Okta JSON is untyped.
export type Row = Record<string, any> & { __ctx?: Record<string, string> };

/** Walk a dotted path through untyped JSON. */
export function at(row: unknown, path: string): unknown {
  let cur: unknown = row;
  for (const p of path.split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

export const asStr = (v: unknown): string | null =>
  v == null ? null : typeof v === "string" ? v : typeof v === "object" ? JSON.stringify(v) : String(v);
export const asBool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : v == null ? null : null);
export const asInt = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : null;
export const asNum = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
/** ISO 8601 → TIMESTAMPTZ microseconds. */
export function asTime(v: unknown): bigint | null {
  if (typeof v !== "string" || v === "") return null;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? null : BigInt(ms) * 1000n;
}
export const asStrList = (v: unknown): string[] | null =>
  Array.isArray(v) ? v.filter((x) => x != null).map((x) => (typeof x === "string" ? x : JSON.stringify(x))) : null;
export const asJson = (v: unknown): string | null => (v == null ? null : JSON.stringify(v));

const JSON_META: [string, string] = ["ARROW:extension:name", "arrow.json"];

function mkCol(
  name: string,
  type: VgiDataType,
  sqlType: string,
  doc: string,
  get: (r: Row) => unknown,
  nullable = true,
): Col {
  return { name, type, sqlType, doc, get, nullable };
}

export const C = {
  str: (name: string, doc: string, path: string | ((r: Row) => unknown), nullable = true) =>
    mkCol(name, utf8(), "VARCHAR", doc, (r) => asStr(typeof path === "string" ? at(r, path) : path(r)), nullable),
  time: (name: string, doc: string, path: string) =>
    mkCol(name, timestampMicros("UTC"), "TIMESTAMP WITH TIME ZONE", doc, (r) => asTime(at(r, path))),
  bool: (name: string, doc: string, path: string | ((r: Row) => unknown)) =>
    mkCol(name, bool, "BOOLEAN", doc, (r) => asBool(typeof path === "string" ? at(r, path) : path(r))),
  int: (name: string, doc: string, path: string) => mkCol(name, int32, "INTEGER", doc, (r) => asInt(at(r, path))),
  num: (name: string, doc: string, path: string) => mkCol(name, float64(), "DOUBLE", doc, (r) => asNum(at(r, path))),
  strList: (name: string, doc: string, path: string | ((r: Row) => unknown)) =>
    mkCol(name, list(utf8()), "VARCHAR[]", doc, (r) => asStrList(typeof path === "string" ? at(r, path) : path(r))),
  json: (name: string, doc: string, path: string | ((r: Row) => unknown)) =>
    mkCol(name, utf8(), "JSON", doc, (r) => asJson(typeof path === "string" ? at(r, path) : path(r))),
  ctx: (name: string, doc: string, key: string) =>
    mkCol(name, utf8(), "VARCHAR", doc, (r) => r.__ctx?.[key] ?? null, false),
  structList: (name: string, doc: string, sqlType: string, fields: { name: string; path: string }[], path: string) =>
    mkCol(name, list(struct(fields.map((f) => field(f.name, utf8())) as never)), sqlType, doc, (r) => {
      const v = at(r, path);
      if (!Array.isArray(v)) return null;
      return v.map((item) => Object.fromEntries(fields.map((f) => [f.name, asStr(at(item, f.path))])));
    }),
};

// --------------------------------------------------------------------- the factory

/** The first request of one phase of a scan. */
export interface PhaseRequest {
  path: string;
  query?: Record<string, string | undefined>;
  /** Per-phase values exposed to columns through `C.ctx` (e.g. the user id). */
  ctx?: Record<string, string>;
}

export interface ScanContext<A> {
  args: A;
  constraints: Constraint[];
  /** Wall-clock anchor fixed when the scan started (epoch ms), stable across resumes. */
  anchorMs: number;
}

export interface FnExample {
  sql: string;
  description: string;
}

export interface OktaTableSpec<A> {
  name: string;
  description: string;
  title: string;
  category: Category;
  keywords: string;
  docLlm: string;
  docMd: string;
  args?: Record<string, VgiDataType>;
  argDocs?: Record<string, string>;
  argDefaults?: Record<string, unknown>;
  argConstraints?: Record<string, Record<string, unknown>>;
  columns: Col[];
  /** One request per phase; an empty list means the scan returns no rows (unused with `fanout`). */
  requests?: (ctx: ScanContext<A>) => PhaseRequest[];
  /** Pull the rows out of a response body (default: the body is the array). */
  rows?: (body: unknown) => Row[];
  /**
   * Per-parent endpoints (members of a group, users of an app …). The parent id is a
   * named argument and an output column (`key`); `key := 'x'` or a pushed
   * `WHERE key = 'x'` / `IN (…)` calls only those parents, otherwise every parent from
   * `parents` is listed (paged) and each one's children are read in turn. The pending
   * parent ids and both cursors live in the scan state, so the fan-out resumes too.
   */
  fanout?: {
    key: string;
    parents: PhaseRequest[];
    parentId: (row: Row) => string | null;
    child: (id: string, scan: ScanContext<A>) => PhaseRequest;
  };
  /** A 404 means "no such object" → zero rows rather than an error. */
  notFoundEmpty?: boolean;
  /** Fan a page of rows out into the emitted rows (extra calls per row). */
  expand?: (cfg: OktaConfig, rows: Row[], ctx: Record<string, string>) => Promise<Row[]>;
  /** Text appended to doc_md describing what pushes down. */
  pushdown?: string;
  examples: FnExample[];
}

interface ScanState {
  phase: number;
  /** Absolute next-page URL; "" = start the current phase from its first request. */
  next: string;
  anchorMs: number;
  /** Fan-out: pending parent ids, newline-joined (the head is being read). */
  queue: string;
  /** Fan-out: index into `fanout.parents` and that listing's next-page URL. */
  parentPhase: number;
  parentNext: string;
}

/** Extract rows from a body that is either an array or a single object. */
function defaultRows(body: unknown): Row[] {
  if (Array.isArray(body)) return body as Row[];
  if (body && typeof body === "object") return [body as Row];
  return [];
}

/** The Arrow output schema of a spec (column comments ride along as field metadata). */
function outputSchemaOf<A>(spec: OktaTableSpec<A>) {
  return schema(
    spec.columns.map((c) =>
      c.sqlType === "JSON"
        ? field(c.name, c.type, c.nullable ?? true, new Map([["comment", c.doc], JSON_META]))
        : column(c.name, c.type, c.doc, c.nullable ?? true),
    ),
  );
}

/** Discovery tags shared by a spec's function or table. */
function tagsOf<A>(spec: OktaTableSpec<A>): Record<string, string> {
  return {
    domain: "identity",
    ...objectTags({
      title: spec.title,
      category: spec.category,
      keywords: spec.keywords,
      docLlm: spec.docLlm,
      docMd: spec.docMd + (spec.pushdown ? `\n\n**Pushdown:** ${spec.pushdown}` : ""),
    }),
    "vgi.result_columns_schema": JSON.stringify(
      spec.columns.map((c) => ({ name: c.name, type: c.sqlType, description: c.doc })),
    ),
  };
}

/**
 * A spec with no arguments exposed as a catalog table (`SELECT … FROM okta.main.policies`).
 * The scan function keeps every capability (pushdown, paging, secrets) and is table-only.
 */
export function defineOktaCatalogTable(spec: OktaTableSpec<Record<string, never>>): TableDescriptor {
  const fn = defineOktaTable({ ...spec, name: `${spec.name}_scan` });
  // Okta object ids are unique and always present: attest it.
  const record = (id: string, kind: "NOT_NULL" | "PRIMARY_KEY") =>
    constraintRecord({
      schemaPath: ["main"],
      table: spec.name,
      id,
      kind,
      columns: [["id"]],
      enforcement: "ENFORCED",
      validation: "ALL_ROWS",
    });
  return {
    name: spec.name,
    comment: spec.description,
    columns: outputSchemaOf(spec),
    function: fn,
    constraints: [record("id_not_null", "NOT_NULL"), record("pk", "PRIMARY_KEY")],
    tags: { ...tagsOf(spec), "vgi.example_queries": JSON.stringify(spec.examples) },
  };
}

export function defineOktaTable<A extends Record<string, unknown>>(spec: OktaTableSpec<A>): VgiFunction {
  const outSchema = outputSchemaOf(spec);
  const extract = spec.rows ?? defaultRows;

  return defineTableFunction<A, ScanState>({
    name: spec.name,
    description: spec.description,
    args: spec.args ?? {},
    argDocs: spec.argDocs,
    argDefaults: spec.argDefaults,
    argConstraints: spec.argConstraints as never,
    filterPushdown: true,
    // DuckDB drops pushed predicates from its plan; the SDK re-applies them exactly,
    // so translating a predicate only ever narrows what Okta returns.
    autoApplyFilters: true,
    onBind: (params) =>
      params.resolvedSecretsProvided
        ? { outputSchema: outSchema }
        : { outputSchema: outSchema, lookupSecretTypes: [SECRET_TYPE] },
    initialState: () => ({ phase: 0, next: "", anchorMs: Date.now(), queue: "", parentPhase: 0, parentNext: "" }),
    process: async (params, state, out) => {
      const cfg = configFromSecrets(params.secrets);
      const scan: ScanContext<A> = {
        args: params.args,
        constraints: constraintsOf(params.pushdownFilters),
        anchorMs: state.anchorMs,
      };
      log.debug(`${spec.name}: pushed filters ${formatPushedFilters(params.pushdownFilters)}`);

      const fetchPage = async (req: PhaseRequest | string) => {
        try {
          return typeof req === "string" ? await oktaGet(cfg, req) : await oktaGet(cfg, req.path, req.query);
        } catch (err) {
          if (spec.notFoundEmpty && err instanceof OktaError && /HTTP 404/.test(err.message)) {
            return { body: [], next: null };
          }
          throw err;
        }
      };
      /** Emit a page's rows; false when there were none (keep reading). */
      const emit = async (body: unknown, ctx: Record<string, string>): Promise<boolean> => {
        let rows = extract(body).map((r) => ({ ...r, __ctx: ctx }));
        if (spec.expand && rows.length) rows = (await spec.expand(cfg, rows, ctx)).map((r) => ({ ...r, __ctx: ctx }));
        if (rows.length === 0) return false;
        const cols: Record<string, unknown[]> = {};
        for (const f of params.outputSchema.fields) {
          const c = spec.columns.find((x) => x.name === f.name);
          cols[f.name] = c ? rows.map((r) => c.get(r)) : rows.map(() => null);
        }
        out.emit(batchFromColumns(cols, params.outputSchema));
        return true;
      };

      const fan = spec.fanout;
      const explicit = fan
        ? typeof params.args[fan.key] === "string" && params.args[fan.key]
          ? [params.args[fan.key] as string]
          : eqValues(scan.constraints, fan.key)
        : undefined;
      const phases = fan ? (explicit ?? []).map((id) => fan.child(id, scan)) : (spec.requests?.(scan) ?? []);

      // Loop until a page yields rows or the scan ends, so no empty batches go out.
      for (;;) {
        if (fan && !explicit) {
          // Org-wide fan-out: refill the parent queue a page at a time.
          if (!state.queue) {
            const pp = fan.parents[state.parentPhase];
            if (!pp) {
              out.finish();
              return;
            }
            const page = await fetchPage(state.parentNext || pp);
            if (page.next) state.parentNext = page.next;
            else {
              state.parentPhase += 1;
              state.parentNext = "";
            }
            state.queue = defaultRows(page.body)
              .map(fan.parentId)
              .filter((x): x is string => !!x)
              .join("\n");
            continue;
          }
          const ids = state.queue.split("\n");
          const id = ids[0] as string;
          const req = fan.child(id, scan);
          const page = await fetchPage(state.next || req);
          if (page.next) state.next = page.next;
          else {
            state.queue = ids.slice(1).join("\n");
            state.next = "";
          }
          if (await emit(page.body, req.ctx ?? {})) return;
          continue;
        }
        const phase = phases[state.phase];
        if (!phase) {
          out.finish();
          return;
        }
        const page = await fetchPage(state.next || phase);
        if (page.next) state.next = page.next;
        else {
          state.phase += 1;
          state.next = "";
        }
        if (await emit(page.body, phase.ctx ?? {})) return;
      }
    },
    tags: tagsOf(spec),
    examples: spec.examples,
  });
}

/** `rel="next"` paging helper for expansions that list a sub-resource fully. */
export async function getAll(cfg: OktaConfig, path: string, query?: Record<string, string>): Promise<Row[]> {
  const rows: Row[] = [];
  let page = await oktaGet(cfg, path, query);
  for (let guard = 0; ; guard++) {
    rows.push(...defaultRows(page.body));
    if (!page.next || guard > 1000) return rows;
    page = await oktaGet(cfg, page.next);
  }
}
