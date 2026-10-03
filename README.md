# Sentinel

A local-first security assessment platform with an original dashboard, private runners, declarative guardrails, CI gates, and application-log monitoring. No SonarQube subscription or connection is required.

## Start locally

Requires Node.js 22+, Python 3.12+, and a browser. Docker Desktop with Linux containers/WSL2 is needed for external scanners, DAST, and the Supabase profile.

```powershell
npm ci
python -m venv .venv
.venv\Scripts\python -m pip install -r runner/requirements.txt
npm run setup
npm run dev
```

Open **http://127.0.0.1:3000**. The setup command creates `.env.local` without overwriting existing settings. Read `LOCAL_PASSWORD` there to sign in. Keep this file private. On Linux/macOS use `.venv/bin/python` instead of `.venv\Scripts\python`.

The public home page describes the assessment features and offers sign-in. The workspace is at `/dashboard`, with a dedicated `/signin` page. Password login remains available; Google login uses Supabase Auth with PKCE when configured. See [Google sign-in setup](docs/google-login.md) for hosted and local authentication settings.

The portable development profile uses persistent **PGlite (embedded PostgreSQL)** in `.data/postgres`. It provides the same SQL schema and API workflow without a Docker database. Local password authentication is development-only; it is disabled in production and on Vercel. This is an additional development mode, not the hosted authentication architecture.

## Connect and scan a project

The **Integrations** page walks through source connection, runner enrollment and startup, shows connection health, and provides CI commands. Run `python -m runner.cli doctor` (optionally `--config runner-settings.json`) to check prepared images, Docker, advisory freshness, and registered roots before scanning.

1. Select **Connect project**, choose a local directory, and enter a source alias such as `my-app`. Do not enter an absolute path in the dashboard.
2. Open **Private runners**, enroll a runner for that project, and download `runner-settings.json`. Its credential is shown once. Move the downloaded file into this repository folder before running the commands below, or pass its full path to `--config`. The registration command updates an existing settings file; it does not enroll a runner or create credentials.
3. Register the source directory on your own machine:

```powershell
python -m runner.cli register --config runner-settings.json --alias my-app --path C:\path\to\app
python -m runner.cli run --config runner-settings.json
```

4. Use **Run assessment** on the project card. The runner receives the frozen project policy, inventories a disposable snapshot, runs checks, and uploads normalized results.
5. Open **Scan history** to inspect engine coverage, errors, metrics, and the quality gate. Review individual findings and suggested remediation.

Runners only poll outbound. Production runner connections require HTTPS. Tokens are scoped to selected projects and stored as hashes on the server. Revoking a token immediately stops new API access. Runner settings are private and ignored by Git.

The included `Security lab` fixtures are deliberately insecure synthetic examples. To run the complete onboarding/scan/rescan/monitoring verification workflow against the development server:

```powershell
python scripts/smoke.py
```

This script creates a named sample project, preserves its reports for review, and revokes its temporary runner credential. It does not scan your unrelated projects.

## Prepare external engines

Start Docker Desktop with Linux containers, then:

```powershell
python -m runner.cli prepare --build-linters
```

Preparation pulls versioned Opengrep, Gitleaks, Trivy, Ruff, and ZAP images; downloads Trivy databases; and builds the ESLint, Checkstyle, Roslyn, Staticcheck, and DAST guard images. It can download several gigabytes. Assessments use `--pull=never`, read-only source mounts, resource limits, and disabled network access. Rerun preparation to refresh advisory databases; databases older than 48 hours make a required dependency gate incomplete.

`runner/adapters.py` contains the explicit engine versions. Preparation locks the downloaded/built scanners to immutable local image IDs in `.data/scanner-images.json`; assessments use those IDs. For distribution, also verify and record the upstream release digests and checksums. Preserve engine license notices and independently audit licenses of added rule packs. The bundled rules are original MIT-licensed rules; Semgrep's restricted registry rules are not bundled.

An unavailable engine produces **unavailable/failed execution metadata and an incomplete gate**, not a clean security assessment. Native scanner mode is intended for trusted local development and has weaker isolation; container mode is the default.

## Guardrails and CI

The **Findings** workbench searches the full finding set with server-side pagination, saved personal views, owner/category/engine/status filters, and bulk assignment. Project settings include business criticality, exposure, default owner and severity-based remediation SLAs. Finding details support investigation notes and due-date overrides. Owner/team values are labels, not permission grants or notification recipients.

Assessment reports provide comparisons, SARIF 2.1.0 exports and CycloneDX downloads when Trivy generated an SBOM. CLI users can add `--sarif artifacts/assessment.sarif`. Failed/partial execution stays visible in SARIF. Configure the consuming tool's entitlement and upload workflow separately.

Optional **Integrations → Refresh public intelligence** enriches up to 100 distinct CVEs using CISA KEV and FIRST EPSS. Only CVE IDs are sent to FIRST. Priority scores include explicit factors and are separate from CI gate severity. Missing data remains unknown; old EPSS does not contribute after seven days.

Use **Guardrails** to save or download `security-guardrails.yml`. It contains only the documented declarative schema: checks, exclusions, severity/rule gates, forbidden architectural imports, forbidden APIs, compiler opt-in, and monitoring thresholds. Unknown keys, commands, and YAML aliases are rejected.

Standalone scans read this file from the target repository. Enrolled scans use the server-side policy frozen when the scan was queued; repository content cannot weaken that policy.

```powershell
python -m runner.cli scan --path C:\path\to\app --enforce --output artifacts\assessment.json
python -m runner.cli scan --path C:\path\to\app --enforce --baseline artifacts\previous.json
```

Exit codes: **0 pass**, **1 policy failure**, **2 incomplete**. Enable merge blocking only after reviewing advisory results. With `new_only: true`, existing findings form the baseline; resolved findings that reappear count as new. Suppressions require a reason and a future expiration. An advisory pass can contain findings; always inspect policy mode and coverage.

For a quick free scan that needs no external engine:

```powershell
python -m runner.cli scan --path fixtures\vulnerable --checks guardrails,quality --enforce
```

These original pattern rules cover review points across JS/TS, Python, Java, C#, and Go. They do not provide complete data-flow analysis or prove exploitability.

## Runtime testing

Attach a local/staging target in project settings and add `dast` to its policy checks. Add the exact same URL to the runner's `allowed_targets` array. Active scans require explicit authorization; passive testing is the default. Production active testing is rejected.

ZAP runs on a disposable **Docker internal network** and can reach only a trusted reverse bridge. The bridge pins and revalidates DNS, validates redirects and paths, enforces exclusions and two requests per second, and rejects arbitrary proxy/CONNECT requests. Only the bridge has external connectivity. A scan has a 30-minute active-testing limit and a 35-minute total limit.

For applications on the Docker host, loopback targets are connected through `host.docker.internal`. The application must be reachable through Docker's host gateway; an application bound strictly to an inaccessible host interface will fail closed. `OpenAPI` is a relative file path inside the snapshotted source. Header authentication is supplied by a credential reference such as `STAGING_AUTH_TOKEN` set on the runner machine. Secrets are never stored in the dashboard target settings.

**Current limitation:** the bridge strips cookies, so cookie/session checks and multi-step browser login are not verified. ZAP scans only discovered routes and supplied API definitions. DAST cannot establish coverage of every application workflow.

## Runtime monitoring

The collector accepts JSON Lines application events and Nginx combined access logs. It allowlists fields, removes sensitive query values, drops bodies/credentials, and checkpoints only after successful delivery. Event identities do not hash raw credentials, bodies, or actor identifiers. Actor identifiers are pseudonymized per organization by the server; paths are stored without query values. Requests matching injection/traversal indicators are classified before query removal.

```powershell
python -m runner.cli collect --config runner-settings.json --project PROJECT_UUID --log C:\logs\app.jsonl --environment local
```

Example event:

```json
{"timestamp":"2026-09-30T20:00:00Z","path":"/login","status":401,"actor":"test-user","auth_outcome":"failure"}
```

Supported security events are `authorization_failure` and `integrity_failure`. Alerts cover failure bursts, denied-request bursts, suspicious paths/injection/traversal, and application security events. Alert evidence is retained separately from scan findings. Correlation requires an explicit `endpoint` URL and `revision` in structured events, matching the finding environment and the same recorded scan revision. Missing metadata prevents correlation; matching paths alone are insufficient. Indicators are not proof of compromise; no telemetry is a coverage gap.

## GitHub and optional AI

Workspace owners use **Integrations → Connect GitHub** to choose an account and repositories on GitHub, authorize the connection, then choose an authorized repository in **Connect project → GitHub repository**. Users never enter app secrets or installation IDs. Connections are verified against GitHub user access, stored per workspace, and limited to repositories the authorizing user can access. Connect again after granting additional repositories. See [GitHub host setup](docs/github-connect.md) for the one-time registration and server configuration. Manual installation mappings are no longer used; existing hosts must reconnect their installations through this flow.

Runner tokens are restricted to the selected repository with contents-read permission; check publishing obtains a separate checks-write token. Project connection verifies repository access with an installation token. Webhooks verify HMAC signatures and deduplicate delivery IDs. Uninstalled or suspended installations are disabled. Same-repository PR updates queue revision-specific scans; fork PRs require explicit scan submission.

GitHub scan credentials are short-lived and passed only to the assigned runner. A failed check publication is recorded in the audit log. Core scanning does not depend on GitHub.

Until branch-specific baselines are implemented, explicit GitHub revision/PR scans conservatively evaluate all reported findings for enforced gates and cannot resolve project-wide baseline findings. This can block existing issues; it prevents a different branch from silently passing or closing the default branch's issues.

Cloud AI is disabled until an API key is configured and AI is enabled on the individual project. Gemini is the default provider, using Google's [OpenAI-compatible Gemini endpoint](https://ai.google.dev/gemini-api/docs/openai). Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/api-keys), then set these server-only variables in `.env.local` (or your hosting environment):

```dotenv
AI_API_KEY=your-gemini-api-key
AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
AI_MODEL=gemini-3.8-flash
```

Restart the application after changing these values, then enable AI and snippet retention in the individual project's settings. Keep the key out of Git and do not prefix it with `NEXT_PUBLIC_`. You can select another compatible Gemini model using `AI_MODEL`; other providers remain supported by setting their HTTPS OpenAI-compatible `AI_BASE_URL` and corresponding key/model.

Only redacted finding context is supplied to the configured provider (Google for the default configuration). The model receives no tools or execution access. Output is a reviewable, unvalidated suggestion and can be downloaded. Curated explanations and supported fix templates work without AI. Cloud provider charges and data handling are separate from this project's free core.

## Supabase / Docker profile

The supplied Compose profile is minimal **Supabase Auth (GoTrue) + PostgreSQL + an auth gateway**, not the entire Supabase Studio/storage/realtime distribution. The application uses server-side SQL and disables direct client access to assessment tables.

```powershell
python scripts/setup-compose.py
docker compose --env-file .env.compose up -d
```

The setup generates `.env.compose` and `.env.supabase.local`. Back up your portable `.env.local`, then select the generated Supabase settings as `.env.local` and restart the dashboard. PostgreSQL is bound to `127.0.0.1:15432`, auth to `127.0.0.1:8000`. Create users through Supabase Auth's `/auth/v1/signup` endpoint or use an existing hosted Supabase account. Local autoconfirm/signup are only for development. Hosted deployments should use verified users/invitations and HTTPS.

Run `npm run migrate` to apply the idempotent schema. Authentication identities obtain a personal organization; owners can add existing user UUIDs as maintainers or viewers in workspace settings. API writes enforce roles and project organization ownership. Runner credentials have a separate authentication path. RLS is enabled and direct `anon`/`authenticated` table grants are revoked; the server connection is privileged and therefore must never be exposed to clients.

## Vercel preview

The app includes `vercel.json`. Set `DATABASE_MODE=postgres`, a server-only Supabase PostgreSQL `DATABASE_URL` (session-mode connection/pooler), `LOCAL_AUTH=false`, a strong `SESSION_SECRET`, HTTPS `APP_ORIGIN`, and matching public/server Supabase URL and anon keys. Configure Next.js public variables **at build time**. Deploy the dashboard only; scan execution remains on private runners. Embedded PostgreSQL and local login refuse Vercel deployment.

No public deployment is made by setup. Vercel Hobby currently limits use to non-commercial personal projects; commercial hosting and paid-worker decisions are intentionally deferred. The complete local core has no service subscription requirement.

## Retention, backup, and verification

Cleanup runs at most hourly when runners poll; use `npm run cleanup` as a scheduled job when no runners are online. Defaults: **30 days** for assessment results and alerts, **7 days** for raw telemetry. Temporary snapshots are deleted after jobs. Changing a project to metadata-only also removes retained evidence/patches from its earlier reports. Explicit project deletion cascades to assessment data and is audited.

For portable-mode backup, stop the dashboard and copy `.data/postgres` plus privately stored configuration; restore with the dashboard stopped. For PostgreSQL use `pg_dump --format=custom` and `pg_restore` into a separate empty database before switching configuration. Never overwrite a live database as a restore test.

```powershell
npm run typecheck
npm test
python -m pytest runner/tests -q
npm run build
```

Tests cover vulnerable/corrected fixtures, tenant access, lease recovery, idempotent report delivery, finding resolution, policy validation, secret redaction, telemetry replay, collector checkpoints, and DAST scope validation. `scripts/smoke.py` exercises real HTTP requests and runner snapshots. Container engine verification requires a functioning Docker daemon and prepared images; unconfigured GitHub/AI providers are not simulated as successful. Real Supabase and scanner checks are recorded in the verification report.

## Coverage and interpretation

- Full **345-requirement ASVS 5.0 catalog** with official provenance and source hashes, searchable coverage states, and export. Findings map to selected exact requirements. Evidence is partial; absence of findings never establishes compliance.
- Complexity and duplication are lexical file-level estimates. Coverage is imported from LCOV/Cobertura, not measured by executing tests.
- C# and Go compiler-dependent checks require opt-in. For standalone scans pass `--compiler-analysis`; repository YAML alone cannot authorize a build. SDK-only C# projects restore against an empty offline feed. External dependencies/build assets must already be available in the snapshot; failures remain visible. Java Checkstyle and JS/Python linting do not require running project startup hooks.
- Gitleaks scans current files and a bounded snapshot of available Git history. Shallow history, unsafe metadata, unavailable worktree pointers, and size omissions are reported explicitly.
- Suspicious install/code patterns are review indicators, not complete malware classification. Unknown malware, business-logic flaws, host/process threats, and full incident response need additional controls.

See [docs/verification.md](docs/verification.md) for the recorded validation and remaining integration limits.

See [docs/industry-gap-review.md](docs/industry-gap-review.md) for the product comparison, delivered upgrades, scoring model, and prioritized remaining gaps. This build is not yet an enterprise-production equivalent of the benchmark products.

## Licenses

Original platform and rule code: MIT. See `LICENSE`. Vendored ASVS requirement data: OWASP Foundation and contributors, **CC BY-SA 4.0**, attributed separately in `data/asvs-5.0.json` and `THIRD_PARTY_NOTICES.md`. External scanner engines retain their own licenses; they are run as separate processes/containers.
