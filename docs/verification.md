# Verification record

Validated locally on Windows with Docker Desktop Linux containers on October 1, 2026. All networked tests use local services or deliberately created fixtures. No personal project was scanned, no real credential was seeded, and no public deployment or paid provider call was made.

## Working implementation

The dashboard, authenticated APIs, PostgreSQL queue, scoped runner, scanner normalization, finding history, declarative policies, CI exit codes, triage, retention, telemetry ingestion, alerts, and ASVS catalog are implemented. The optional embedded PostgreSQL profile makes the local dashboard usable without running a database container. The Compose profile uses real PostgreSQL and Supabase Auth.

## Executed checks

Final verification: the production build passed, all 9 Node test groups and 22 Python runner tests passed, and the HTTP/container workflow, passive ZAP, and Supabase checks passed after the final schema and credential-isolation changes. Tests include exact endpoint/environment/revision correlation without cross-pair matches and explicit CLI authorization for compiler-dependent analysis.

### Industry-gap upgrade verification

The subsequent workbench/integration upgrade passed 13 Node test groups and 24 Python tests, TypeScript checking and the production build. The real Opengrep container detected all five newly added rule fixtures and cleared their safe controls (`scripts/verify-rules-v2.py`). The updated HTTP/container smoke exercised full-set finding pagination, assignment, notes, SARIF/CycloneDX export, comparisons, and integration diagnostics. The standalone CLI produced a passing corrected-fixture report plus SARIF. `runner.cli doctor` confirmed all ten engine images and a fresh advisory cache. The expanded database schema also passed the real local Supabase check.

Browser verification covered workbench loading, accessible filtering, saving a personal view, displaying ownership and notes, modal Escape dismissal, and the integration center. Intelligence parsing, unavailable-feed preservation, risk scoring and tenant isolation were exercised with controlled responses. `scripts/verify-intelligence.ts` additionally passed live CISA/FIRST feed retrieval and normalization for the public Log4Shell CVE in a disposable in-memory database. Downstream SARIF ingestion has not been validated against production accounts. See [the gap review](industry-gap-review.md) for explicit remaining product gaps.

| Check | Evidence |
| --- | --- |
| Production dashboard | `npm run build`; TypeScript compilation and dynamic routes passed |
| API/database/security tests | `npm test`; organization and role isolation, CSRF origin checks, scoped/revoked runner credentials, leases, duplicate completion, baseline/resolution, expired suppression, signed/deduplicated GitHub webhooks, metadata purging, telemetry deduplication and normal-traffic controls |
| Runner tests | `python -m pytest runner/tests -q`; five-language vulnerable/corrected pairs, stable identities, snapshot limits, policy validation, redaction, collector checkpoints, DAST scope/DNS/redirect checks, rejected credentials and request budgets |
| HTTP and enrolled runner | `python scripts/smoke.py --containers`; real onboarding, queue claim, report submission, findings, pass/fail/incomplete gates, alert ingestion, ASVS evidence, and credential revocation |
| Real scanner engines | `python scripts/verify-containers.py`; Opengrep detects all five vulnerable language fixtures, corrected fixtures clear them, Gitleaks directory scan, Trivy vulnerable Flask dependency/Dockerfile/SBOM, ESLint/Ruff/Checkstyle |
| Original data-flow rules | `python scripts/verify-taint.py`; Express and Flask-style request data reaches SQL text; parameterized-query controls do not alert |
| Historical secrets | `python scripts/verify-history.py`; a removed synthetic token remains detectable in available Git history; repository allowlists cannot suppress platform checks; evidence remains masked |
| Opt-in compilation | `python scripts/verify-compilers.py`; Roslyn CS0219 and Staticcheck SA5009 are detected and clear after correction in isolated offline builds |
| Real DAST | `python scripts/verify-dast.py`; passive ZAP against a disposable local server through the isolated scope guard, with normalized endpoint evidence |
| Supabase | `npx tsx scripts/verify-supabase.ts`; real signup/token validation, organization bootstrap, RLS and restricted direct table grants; disposable identity removed afterward |
| Backup/restore | `python scripts/verify-backup.py`; `pg_dump` restored into a new disposable database, assessment tables checked, only that test database removed |
| Dependencies | `npm audit --omit=dev`; zero reported vulnerabilities at verification time |
| Browser | Local sign-in, finding evidence/remediation, ASVS catalog, scan reports, and responsive navigation reviewed in the in-app browser |

Redacted integration reports are written under ignored `artifacts/`. A clearly named synthetic security-lab project remains in the local dashboard for review. Its temporary runner credentials are revoked. To assess another project, enroll your own scoped runner and register its source alias.

## Tested coverage matrix

| Ecosystem | Verified analysis | Limits |
| --- | --- | --- |
| JavaScript / TypeScript | Original AST rules, Express-style request-to-SQL taint, dangerous API guardrails, ESLint | Selected rules and request syntax only; no complete frontend/Express/Next/Vue framework certification |
| Python | Original AST rules, Flask-style request-to-SQL taint, deserialization/command guardrails, Ruff | Django request syntax has rules; full Django authorization/business logic needs manual review |
| Java | Original AST deserialization rule, process/deserialization guardrails, Checkstyle | Spring is inventoried; Spring-specific authorization and business logic are not comprehensively tested |
| C# | Original AST deserialization rule, TLS/deserialization guardrails, opt-in Roslyn | Package-dependent builds require offline assets; custom MSBuild tasks run only in the opted-in disposable container |
| Go | Original AST TLS rule, shell/TLS guardrails, opt-in Staticcheck | External modules require offline assets; build failures remain visible |

Framework detection is inventory information. It does not automatically confer framework-specific security coverage. Unsupported ASVS requirements remain explicitly unsupported; mapped checks can still require manual review. A clean scan is never converted into a compliance claim.

## Integration and release limits

- GitHub App credential issuance, repository clone permissions, actual revoked-installation behavior, and check publication need a configured real GitHub App. Signed webhook handling and tenant installation binding are tested locally. Installations must be explicitly bound to organizations by the server administrator.
- Cloud AI is implemented behind project opt-in and a server-side user-supplied key. No paid provider was called. Provider availability, generated patch correctness, and adversarial model behavior require evaluation against the selected provider before enabling it for sensitive projects. AI has no tools or execution privileges.
- ZAP passive operation is verified. Active profiles and OpenAPI discovery are implemented, but large applications and full authenticated workflows still need target-specific acceptance testing. The bridge intentionally omits cookies; browser login, cookie/session controls, and transport-specific assertions need manual review.
- Available Git history is bounded to 50 MB and 10,000 metadata files. Shallow history is identified, external object stores and hooks/config are not copied, and worktree `.git` pointers are not followed outside the registered root.
- Source safety ceilings are 20,000 files, 2 MB per file, and 100 MB total. These are isolation limits, not supported-size performance promises. Integration reports contain elapsed engine timings. Representative large-project CPU/memory benchmarks and malicious resource-exhaustion testing are still required before setting commercial capacity guarantees.
- Monorepo component roots and framework labels are supported. A project currently has one runtime target; separate runtime environments can be represented by separate projects sharing the repository.
- Organization isolation and roles are implemented and tested locally. The Vercel/Supabase deployment profile is supplied, but no hosted deployment or hosted/private-runner parity test was performed without account configuration.
- These tests do not replace an independent security review of the assessment platform itself. Full penetration testing, exhaustive business-logic review, fuzzing, IAST, host malware agents, automatic fixes, and commercial operation remain outside this local alpha.

## Updating scanners

Prepare engine images deliberately, preserve notices, and run fixture checks before using an update. Preparation records immutable local image IDs in `.data/scanner-images.json`; assessment jobs use those IDs and never pull images or update advisory databases. Refresh Trivy databases explicitly; missing or stale data produces an incomplete required check. Platform-owned rule/config mounts prevent repository-provided scanner exclusions from weakening an enrolled assessment.

## Runner configuration recovery

The Python suite now passes 35 tests, including missing configuration errors for every config-enabled command, malformed settings without credential disclosure, UTF-8 BOM support, registration preserving existing settings, and missing source paths without mutation. The configured local WalletAce runner passed read-only prerequisite checks for Docker, all prepared images, advisory freshness, and its registered directory. These checks do not run an assessment.

## Public home page and Google sign-in

21 Node tests pass, including Google-provider configuration, fixed callback destinations, malformed/cancelled OAuth parameters, verified identity precedence, and organization isolation. TypeScript checks and the production build pass for /, /signin, /dashboard, and /auth/callback. Live HTTP checks confirm the existing local password opens the WalletAce workspace and logout restores API protection. Browser checks confirm the public feature overview, sign-in navigation, incorrect-password feedback, safe OAuth cancellation, and mobile sign-in with no horizontal overflow at the tested breakpoint. Google consent and a real provider callback require user-configured credentials and were not executed.
