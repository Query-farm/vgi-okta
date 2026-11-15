/**
 * Assemble the `okta` catalog: the table functions, the parameterless collections as
 * tables, and the `okta` secret type.
 */

import { type CatalogDescriptor, field, schema, utf8, type VgiFunction } from "@query-farm/vgi";
import { CATALOG_COMMENT, CATALOG_NAME, CATALOG_TAGS, SCHEMA_DOC_MD, SCHEMA_TAGS, SOURCE_URL } from "./meta.ts";
import { SECRET_TYPE } from "./okta/client.ts";
import { FUNCTIONS, TABLES } from "./okta/resources.ts";

export { FUNCTIONS };

const doc = (text: string) => new Map([["vgi_doc", text]]);
const redacted = (text: string) =>
  new Map([
    ["redact", "true"],
    ["vgi_doc", text],
  ]);

/** CREATE SECRET (TYPE okta, ORG_URL '…', API_TOKEN '…') — or CLIENT_ID + PRIVATE_KEY. */
export const OKTA_SECRET_TYPE = {
  name: SECRET_TYPE,
  description: "Okta org URL plus an SSWS API token or an OAuth 2.0 service app (private_key_jwt)",
  schema: schema(
    [
      field(
        "org_url",
        utf8(),
        true,
        doc("Your Okta org URL, e.g. https://acme.okta.com (http:// is accepted only for 127.0.0.1/localhost)."),
      ),
      field(
        "api_token",
        utf8(),
        true,
        redacted("SSWS API token (Security > API > Tokens). Use this or CLIENT_ID + PRIVATE_KEY."),
      ),
      field(
        "client_id",
        utf8(),
        true,
        doc("OAuth 2.0 service app client id (for private_key_jwt instead of an API token)."),
      ),
      field(
        "private_key",
        utf8(),
        true,
        redacted("The service app's private key: PEM (PKCS#8 or PKCS#1) or a JWK JSON object; RSA or EC P-256."),
      ),
      field("key_id", utf8(), true, doc("Optional key id (kid) of the service app's public key.")),
      field(
        "scopes",
        utf8(),
        true,
        doc("Space-separated okta.*.read scopes to request; defaults to the read scopes every function needs."),
      ),
    ],
    new Map([["vgi_doc_url", "https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/"]]),
  ),
};

interface Example {
  description: string;
  sql: string;
}

/** Publish each function's examples as `vgi.example_queries`; return them all for the schema. */
function stampExampleQueries(functions: VgiFunction[]): Example[] {
  const all: Example[] = [];
  for (const fn of functions) {
    const ex = (fn.meta.examples ?? []).map((e) => ({ description: e.description, sql: e.sql }));
    fn.meta.tags = { ...fn.meta.tags, "vgi.example_queries": JSON.stringify(ex) };
    all.push(...ex);
  }
  return all;
}

const ALL_EXAMPLES = [
  ...stampExampleQueries(FUNCTIONS),
  ...TABLES.flatMap((t) => JSON.parse(t.tags?.["vgi.example_queries"] ?? "[]") as Example[]),
];

export const CATALOG: CatalogDescriptor = {
  name: CATALOG_NAME,
  comment: CATALOG_COMMENT,
  sourceUrl: SOURCE_URL,
  tags: CATALOG_TAGS,
  secretTypes: [OKTA_SECRET_TYPE],
  schemas: [
    {
      path: ["main"],
      comment: SCHEMA_DOC_MD,
      functions: FUNCTIONS,
      tables: TABLES,
      tags: { ...SCHEMA_TAGS, "vgi.example_queries": JSON.stringify(ALL_EXAMPLES.slice(0, 12)) },
    },
  ],
};
