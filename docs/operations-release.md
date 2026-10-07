# October 7, 2026 reliability and collaboration release

This release is a production-deployed private alpha, not a claim of enterprise readiness or exhaustive vulnerability detection. The October 1 review in `industry-gap-review.md` remains historical; this document supersedes its implementation status where stated below.

## Delivered

- Immutable source/component/target settings at queue time, branch-specific finding occurrences, conservative explicit-commit gates, and idempotent scan submission. Historical job snapshots are marked backfilled: their original settings cannot be recovered. Run a fresh default-branch assessment before relying on migrated branch comparisons.
- Paginated scan, alert and audit history; per-project Operations showing runner assignments, queued jobs, DAST configuration and collector health.
- Workspace switching, owner-created invitations bound to a verified Supabase email, seven-day expiry and revocation; invitations show a code once and send no email. Existing roles are preserved when an existing member redeems a code. Shared workspace finding views are published by maintainers.
- Expiring manual ASVS review evidence, visible to viewers and distinct from automated coverage. Thirty-day assessment trends and an observed resolution-time summary; these are limited by retention and are not a complete reopened-issue MTTR model.
- Versioned `/api/v1` routes, authenticated OpenAPI discovery and a source TypeScript client in `lib/sdk.ts`. The specification is explicitly partial: endpoint-specific request/response schemas and a published SDK remain open work.
- Bounded SBOM dependency relationship traversal through `/api/v1/scans/{id}/dependency-paths?package=...`. Versions and declared licenses are preserved. Missing relationships remain unknown; this is not function reachability or a license legal assessment.
- Python AST function complexity and optional imported-coverage/function-complexity gates. Missing/invalid required metrics produce incomplete gates. Other-language metrics remain estimates; imported coverage does not establish tested-revision provenance or new-code coverage.
- Original JavaScript/Python request-to-HTTP SSRF taint rules with real Opengrep vulnerable/corrected controls. Framework coverage remains bounded and non-exhaustive.
- Optional bounded, redacted source context for selected remediation suggestions. Metadata-only projects retain no snippets or patches. AI remains opt-in, has no execution privileges and proposes reviewable, unvalidated changes.
- `python -m runner.cli validate-patch --path PROJECT --patch PATCH` checks applicability on a disposable snapshot. It never edits the original project, runs build hooks or claims security validation.
- Fixed-cookie DAST authentication with protected-endpoint verification and redirect rejection, in addition to existing header credentials. Multi-step login, rotating sessions, browser authentication and AJAX crawling remain separate work.
- Private-runner supervisor with restart, heartbeat state, log rotation and controlled daily advisory maintenance. Database refresh drains workers before modifying shared advisory data.
- Production daily retention endpoint protected by a production-only secret. Default retention remains 30 days for assessment results and seven days for raw runtime events.

## User-specific runtime setup

Each maintainer selects their own project and configures its exact local/staging URL, exclusions, request limits and authorization through project settings. Passive analysis is the starting mode; active scanning requires explicit project authorization. Authentication secrets remain runner-local. Rebuild the trusted DAST guard and prepare/lock images after upgrading runner code.

Each collector is configured on the machine that can read that project's application/proxy logs. It sends allowlisted events and a keyed source identifier, never its local log path. Quiet sources still heartbeat. Events older than seven days are skipped and counted; future timestamps beyond 60 seconds stop delivery without advancing the checkpoint. Correct the application clock and retry. Cumulative parsing gaps remain visible until the checkpoint is deliberately reset. A collector heartbeat failure does not rewind acknowledged events. No project URL or log path is inferred from another user's setup.

## Private-runner operations on Windows

Use `scripts/runner-startup.ps1 -Action Install` to register a limited current-user logon task. `Start`, `Stop`, `Status`, and `Remove` manage that task. The machine must be on and the user must be logged in; this is not an always-on cloud worker. `runner-service.ps1` reads the ignored `.data/runner-service.json` manifest. Tokens remain only in ignored runner configuration files. Logs and supervisor state live under `.data/supervisor`.

Run `python -m runner.cli doctor --config CONFIG` for prerequisites. It checks Docker, prepared images and advisory freshness, not repository permissions or target authentication. Run `refresh-db --config CONFIG` deliberately when no assessment is using the shared database, or use supervisor-controlled maintenance. Failed engines and stale/future advisory timestamps must remain incomplete.

## Release and recovery

Before deploying, back up the hosted PostgreSQL database using the database provider's backup/export procedure and protect the export as sensitive data. Schema additions are additive and initialized under an advisory transaction lock. A code rollback must preserve these additions; historical data should not be removed to roll back a UI. Restore rehearsals, migration rollback drills, operational SLOs and high availability remain unverified requirements.

The linked GitHub `main` branch deploys to the existing Sentinel Vercel project. Configure `CRON_SECRET` only in production. Vercel sends its Bearer credential to `/api/maintenance/cleanup` daily at 06:00 UTC; manual unauthenticated calls must be rejected. Never expose this secret to browser JavaScript. Cleanup is throttled. Verify the deployment commit, protected endpoint, cron schedule and private-runner health after release.

## Open roadmap and assurance work

## Verification recorded October 7

The final regression run passed 62 Node tests and 53 Python runner tests. TypeScript and the production build passed. Real Opengrep SSRF vulnerable/corrected fixtures, real ZAP passive testing and isolated cookie-authenticated protected-endpoint testing passed. These are bounded controls, not an exhaustive detector benchmark.

The production release was verified as Ready on Vercel. Signed-in Operations reported one online scoped runner for each existing project. Assessments submitted through the production UI completed: EvalsAI at revision `a9ed2a1ac420` passed its advisory gate; Sentinel at `275413fb9acb` reported incomplete lint coverage because C# Roslyn and Go Staticcheck compiler analysis had not been opted into. Other required engines completed. This limitation must not be hidden or converted into a pass.

Production `/api/v1/health` returned 200; unauthenticated Operations and maintenance requests returned 401. Vercel displayed the enabled daily 06:00 UTC retention schedule, and its authenticated Run action returned 200 in runtime logs. No real application DAST URL or log collector was configured for either project: that setup belongs to each project's user.

## Remaining assurance and product work

| Area | Remaining work |
| --- | --- |
| Platform assurance | Independent threat modeling and penetration testing, malicious-container exhaustion tests, PostgreSQL load/concurrency tests, backup/restore rehearsal, release signing |
| Analysis | Interprocedural/framework modeling, public benchmark precision/recall, broader auth/access-control rules, supported-size resource benchmarks |
| Scan lifecycle | Explicit branch merge/deletion lifecycle; resolution comparability when exclusions/component scopes change; archival lifecycle beyond retention |
| DAST | Browser/AJAX discovery, multi-step and rotating authentication, sustained authenticated coverage and larger active/OpenAPI suites |
| Identity | Per-project grants, SSO/SAML/SCIM, MFA enforcement and session administration |
| Supply chain | Tested function reachability, enforceable license policy, signed VEX, malicious-package intelligence and safe secret validity verification |
| Quality | AST metrics across all ecosystems, revision-bound test provenance, new-code duplication/coverage and incremental analysis |
| Integrations | GitLab/Bitbucket/Azure DevOps, issue tracker adapters, signed retryable notifications, scoped service tokens, IDE/LSP, complete public API contract |
| Monorepos | Per-component policies/ownership/compiler roots, multiple runtime targets and scalable scheduling |
| Remediation | Isolated checks for proposed fixes, review approval and exception queues, escalation and owner-directory integration |
| Monitoring | OpenTelemetry adapters, clock-error health reporting, sustained traffic tuning and investigated-alert correlation |
| Governance | Custom control catalogs, complete risk trends, tamper-evident audit retention |

Automatic source edits, public scanning, paid execution, fuzzing, IAST and host malware agents remain outside this release. A clean assessment does not certify compliance or prove freedom from malware.
