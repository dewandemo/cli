# PARTIAL project-copy planning: secrets only

This release inventories source-project secrets and reports capabilities only.
**It does not create/check a destination, copy anything, or establish readiness.**
Connectors, pipelines and all other project resources are **NOT INVENTORIED**.
Apply, mappings and non-secret selections are unavailable; unsupported selections
are rejected before inventory. The destination must be distinct and explicit.

```sh
harness migrate project:project --from source_project --to destination_project --org example_org --resources secret --dry-run
harness migrate project:project --from source_project --to destination_project --org example_org --resources secret --json --out new-report.json
```

Normal profile/environment authentication and `--org` resolution apply. The
profile's default project is ignored: neither `--from` nor `--to` defaults.
Explicit `--project` and non-project `--level` are rejected. Omit `--dry-run` for
the same read-only behavior; there is no apply implementation. `--apply` and
explicit `--dry-run=false` error before inventory.
No confirmation, `--force`, resource files or checkpoint/resume path exists.

## Safe reports and exit status

Text (default), `--format text`, `--format json` and `--json` report the same
PARTIAL scope and completion status. `--raw` cannot reveal raw definitions: only
the safe report ever reaches output. `--out` exclusively creates a **new**, mode
0600 file; existing files and symlink/hardlink aliases are never overwritten.
There is no separate report-file flag. Output errors do not print file contents
or source response text. Shell redirection remains the caller's responsibility.

Secret entries use report-local ordinals, fixed type/capability labels and fixed
reasons, not names/identifiers, values, manager identifiers, locators, descriptions,
raw definitions or hashes. Definitions are memory-only, never debug logged.

| Capability | Meaning in this release |
| --- | --- |
| `reference-only` | Known external SecretText Reference configuration; no value export. Manager/destination access and mapping remain unverified. |
| `mapping-required` | SecretText Inline values are non-exportable; secure provisioning or verified shared mappings are needed later. |
| `blocked` | Unsupported/missing/unknown fields or types; no copy support is claimed. |
| `copyable` | Reserved capability vocabulary; **never assigned** without proven dependency/access/apply contracts. |

Only the documented minimal SecretText schema is classified as reference-only or
mapping-required. Additional metadata, other secret types, unknown/control fields
and unproven variants block; no writable definition is produced or retained for
apply. A complete reference inventory can exit zero, including an empty inventory;
this means only read-only inventory completion, **not copy readiness**. Required
mappings, blocked variants, denied reads or incomplete inventories exit nonzero.
A failed inventory report has `inventory_complete: false`; earlier entries are
only partial observations. A complete inventory may still contain blocked items.

Malformed-response errors identify `initial-list`, `detail`, or
`consistency-relist` using fixed reason codes, allowlisted schema object/field
paths, and JSON-kind labels. Unknown context is `unknown`; received keys,
values, parser messages, request/auth data and response bodies are never shown.
These diagnostics do not establish API compatibility or resolve a failed read.

## Public contracts and offline validation

- [List API](https://apidocs.harness.io/secrets/listsecretsv4): read-only `POST /ng/api/v2/secrets/list/secrets`, `filterType: Secret`, scoped account/org/project, zero-based `pageIndex`, maximum `pageSize: 100`, response `totalItems`, `totalPages`, `pageItemCount`, `pageSize`, `content[].secret` and `updatedAt`.
- [Detail API](https://apidocs.harness.io/secrets/getsecretv2): scoped `GET /ng/api/v2/secrets/{identifier}`, `data.secret` and `updatedAt`.
- [Harness SecretText SDK schema](https://github.com/harness/harness-go-sdk/blob/2d590feb560bb8609bef3f96e73601602b13574b/harness/nextgen/model_secret_text_spec.go): `type`, `secretManagerIdentifier`, `valueType`, optional `value` and `additionalMetadata`. Only the minimal variant without additional metadata is supported here.

Inventory validates all pagination metadata, counts, unique identities, source
scope and list/detail type/revision agreement. Present `pageIndex` and `empty`
controls must match the requested page and content; `pageToken` must be an empty
string because token-based continuation is not supported. Unknown page controls,
case aliases, null controls and unsupported list-secret fields fail closed.
Documented optional controls may be omitted, including `draft` (default false).
It re-lists after details and rejects observed churn. This is not an atomic server snapshot or a guarantee
against a change after the final read. Missing/restricted/inconsistent results
are never interpreted as an empty inventory. Inventories over 100,000 items or
responses over 4 MiB fail closed rather than being silently truncated.

The module's authenticated raw transport allows only the documented list and
detail reads, disables redirects, discards response/error bodies from diagnostics,
and makes at most three attempts for network/429/502/503/504 failures. Bounded,
cancellable delays honor Retry-After; waits above ten seconds fail for a later
manual retry, not an early request. Other status/schema errors are not retried.

Tests use synthetic public-contract fixtures and fake transports for pagination,
scope/access failures, malformed/truncated responses, churn, capabilities,
retries, no mutation paths, sensitive-marker absence and protected report files.
**No live Harness reads, profiles or resources were used.** Mocks validate local
behavior, not live API conformance, permission completeness or operational readiness.
