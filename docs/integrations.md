# Integration reference

Use a Supabase user access token as `Authorization: Bearer …` for application APIs. Select an existing organization membership with `X-Organization-Id`. Do not send runner credentials to user APIs or use the local development password in hosted CI. Runner tokens are scoped to the separate `/api/runner/*` endpoints. Every endpoint below requires authentication and organization authorization.

| Method / endpoint | Purpose | Permission |
| --- | --- | --- |
| `GET /api/findings` | Full-set paginated search | Viewer or above |
| `GET /api/findings/summary` | Aggregate finding counts by status/category/severity and overdue counts | Viewer or above |
| `POST /api/findings/assign` | Atomic assignment of 1–100 findings with optional deadline | Maintainer or owner |
| `GET /api/findings/{id}/notes` | Latest 100 investigation notes | Viewer or above |
| `POST /api/findings/{id}/notes` | Add a redacted note | Maintainer or owner |
| `GET /api/views` | Personal saved searches | Authenticated member |
| `POST /api/views` | Save personal filters | Authenticated member |
| `DELETE /api/views/{id}` | Delete your own saved view | View owner |
| `PUT /api/projects/{id}/context` | Business context and severity SLAs | Maintainer or owner |
| `GET /api/scans/{id}/sarif` | SARIF 2.1.0 with engine execution metadata | Viewer or above |
| `GET /api/scans/{id}/sbom` | Trivy-produced CycloneDX document; 404 when unavailable | Viewer or above |
| `GET /api/scans/{id}/compare?base={scanId}` | Compare two completed scans of the same project | Viewer or above |
| `GET /api/integrations` | Organization runner/service status | Viewer or above |
| `POST /api/intelligence/refresh` | On-demand public CVE enrichment | Owner |

Finding query parameters: `project` (UUID), `q` (text), `severity`, `status` (`actionable`, `all`, or a triage status), `category`, `engine`, `assignee` (label or `unassigned`), `overdue` (`all`/`yes`), `sort` (`priority`/`newest`/`oldest`/`due`), `page` (starts at 1), `limit` (1–100; default 25). Invalid parameters are rejected. Response: `items`, `total`, `page`, `limit`, `pages`. Ordering is deterministic with a finding-ID tie-breaker; offset pages are live views, not an immutable export snapshot.

Finding items expose `priority` (`P0` immediate, `P1` high, `P2` medium, `P3` low, `P4` informational) and explanatory `priority_reasons`. Severity remains the scanner's original classification. Priority sorting retains risk ordering within each tier.

Assignment example:

```json
{"ids":["FINDING_UUID"],"assignee":"Payments team","due_at":"2026-12-01T23:59:59Z"}
```

Use `assignee: null` to inherit the project owner, `assignee: ""` to leave explicitly unassigned, and `due_at: null` to inherit the project SLA. Assignments do not grant access or send messages. Notes accept `{"body":"Investigation and remediation evidence"}` and redact recognizable credentials before storage. Suppression remains a separate triage action requiring a reason and expiration.

## CLI and CI

Install Sentinel on a disposable or trusted worker, prepare its engine images and advisory cache, and execute it from its trusted installation directory. Keep the assessed repository in a separate checkout. The ordinary scan does not run install hooks or repository startup commands.

```sh
python -m runner.cli doctor
python -m runner.cli scan --path /workspace/app --enforce --output artifacts/assessment.json --sarif artifacts/assessment.sarif
```

Exit codes are 0 pass, 1 gate failure, 2 incomplete. Always archive reports even on a nonzero exit. `--baseline /trusted/previous.json` applies a reviewed prior report. `--compiler-analysis` separately opts into isolated builds. The repository policy alone cannot enable compilation.

[GitHub's SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github) describes the supported upload action/API and repository entitlements. Pin actions and the trusted Sentinel version when configuring your CI. The platform does not automatically write CI files into connected repositories or publish results to external services. Native GitLab security dashboard formats require a separate adapter; SARIF can still be archived as a CI artifact.

Public-feed refresh sends CVE identifiers to FIRST, never repository source. Missing feeds preserve previous observations. For a live, public-data-only integration test, run `npx tsx scripts/verify-intelligence.ts`; it uses an in-memory database and no account credentials.

The current reference describes the implemented API; a complete versioned OpenAPI contract and generated SDK remain on the product roadmap.
