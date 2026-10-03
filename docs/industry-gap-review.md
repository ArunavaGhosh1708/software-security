# Product gap review and implemented upgrades

Reviewed October 1, 2026 against the running implementation and current primary documentation. This is a scoped engineering assessment, not proof that every competing product or every security weakness has been evaluated. The application remains a local alpha; this update does not establish enterprise readiness or equivalent detection depth.

## Benchmarks used

- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support): standardized findings, fingerprints, file locations, and execution metadata.
- [DefectDojo finding workflows](https://docs.defectdojo.com/asset_modelling/engagements_tests/os__findings/) and [asset context](https://docs.defectdojo.com/asset_modelling/engagements_tests/pro__assets/): ownership, remediation deadlines, context, and exploitability enrichment.
- [Sonar quality gates](https://docs.sonarsource.com/sonarqube-community-build/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates): new-code conditions, coverage and duplication controls. Existing Sentinel lexical metrics do not match this analysis depth.
- [CycloneDX SBOM](https://cyclonedx.org/capabilities/sbom/): components, versions, and dependency relationships in an interoperable report.
- [FIRST EPSS data](https://www.first.org/epss/data.html) and [API](https://api.first.org/epss/): public exploit probability data, freshness, and bounded lookup usage.

## Changes delivered in this update

| Gap found | Change | Boundary |
| --- | --- | --- |
| Findings silently limited to the latest 1,000 | Paginated SQL-backed search across the organization's complete finding set; severity, status, category, engine, owner, overdue and sort filters | Overview still has explicit preview limits; scan and alert history need their own paginated explorers |
| Repeat triage required manual filtering | Personal saved views | At most 30 per user; shared team views and view deletion UI remain future work |
| No remediation accountability | Per-finding/team assignment, atomic bulk assignment, redacted investigation notes, project owners and severity SLAs | Owner names are labels; they do not grant permissions or send notifications |
| Severity alone drove ordering | Explainable P0–P4 priority from severity, owner-supplied asset context, KEV and fresh EPSS | Heuristic tiers; no reachability claim |
| Dependency details were lost | Preserve package/version/fix/purl/ecosystem/CVSS and advisory identity | Existing stored reports need rescanning for additional metadata |
| Vendor-specific export only | SARIF 2.1.0 from API and CLI, stable fingerprints, safe source URIs, failed execution metadata; CycloneDX download | External ingestion/account entitlement is not verified; no claim of native GitLab security-report compatibility |
| Hard to understand differences between scans | New/persistent/no-longer-detected/not-rechecked comparison | Changed coverage or failed engines stay not rechecked; DAST absence never becomes a candidate fix here |
| Difficult runner setup diagnosis | Read-only `doctor` command and integration center with onboarding steps and connection status | Does not validate target credentials or GitHub installation access |
| Narrow rule set | Five additional original AST/taint checks with vulnerable/corrected controls | Syntax and framework patterns remain bounded; not comprehensive interprocedural analysis |
| Concurrent scans could race baseline updates | One active scan per project with queue row/project locking | Multi-project workers remain independent |
| PR results could close default-branch findings | Explicit GitHub revisions cannot resolve project-wide baseline findings; enforced gates conservatively evaluate all their findings | Full branch-specific baselines still required for precise new-only PR gating |
| Coverage accumulated old successful engine runs | ASVS uses executions from each project's latest assessment | Findings can preserve older evidence; automated evidence still does not certify requirements |
| Modal keyboard navigation incomplete | Initial focus, focus containment, Escape dismissal, focus restoration, inert background | Screen-reader and assistive-technology matrix remains to be tested |
| AI provider transport underconstrained | HTTPS-only base URLs with redirects rejected | Provider evaluation and adversarial prompt tests remain outstanding |

## Priority calculation

The dashboard and findings API expose priority tiers: **P0 Immediate**, **P1 High**, **P2 Medium**, **P3 Low**, and **P4 Informational**. Risk factors can escalate a finding above its original severity tier. Source severity and existing CI gate semantics are preserved.

Internal ordering starts at critical 75, high 55, medium 30, low 10, informational 0. Add 5 for important assets or 10 for critical assets, 10 for owner-declared internet exposure, 25 for known exploitation in CISA KEV, and 10 for EPSS at least 0.10 published within the last seven days. Cap at 100. Convert to P0 at 75+, P1 at 50–74, P2 at 25–49, P3 at 10–24, and P4 below 10. Numeric ordering values are internal; API items return `priority` and `priority_reasons`. Unknown exposure and missing intelligence remain unknown rather than inferred.

On-demand enrichment queries at most 100 distinct CVEs per organization; failed feeds preserve previous observations. EPSS data older than seven days stops contributing to priority. A historical positive KEV observation remains a conservative risk signal. Refresh is an owner action, limited to two per hour, and does not send snippets or project names to providers.

## Remaining product gaps, ordered by delivery priority

| Priority | Capability | Work needed to meet a mature production benchmark |
| --- | --- | --- |
| P0 | Platform security assurance | Independent threat model, penetration test, malicious repository/container escape and resource-exhaustion testing, dependency provenance review |
| P0 | Analysis depth and precision | Expand original/licensed rules, interprocedural and framework modeling, SSRF/auth/access-control checks, public benchmark evaluation, measured false-positive/false-negative rates |
| P0 | Baselines and scan scope | Branch/PR-specific finding lifecycle, immutable target/component configuration per job, migration-tested branch identities; current explicit-commit policy is conservative |
| P0 | DAST fidelity | Browser and cookie/session authentication, logout detection, AJAX crawling, verified authenticated coverage, larger active/OpenAPI acceptance suites |
| P0 | Operational scale | Pagination for scans/alerts/audits, bounded large-report storage, representative benchmarks, PostgreSQL concurrency/load tests, retention sizing, HA/restore drills |
| P1 | Identity and organizations | Organization switching/invitations, per-project grants, SSO/SAML/SCIM integration, MFA enforcement, session administration, credential rotation/expiration |
| P1 | Supply-chain context | Transitive dependency paths, tested function reachability, license policy, signed VEX, malicious package evidence, secret validity verification without exposing credentials |
| P1 | Release quality | AST-level function metrics, new-code coverage and duplication gates, test provenance, incremental scans; current metrics remain lexical estimates |
| P1 | Integration breadth | Tested real GitHub App lifecycle, GitLab/Bitbucket/Azure DevOps adapters, Jira integrations, signed retryable notification webhooks, scoped service API tokens, IDE/LSP support |
| P1 | Monorepo UX | Per-component policies, compiler roots, multiple runtime targets, component ownership and scalable scheduling |
| P1 | Remediation workflow | Validated patch testing, issue linking, owner lookup, automatic escalation/notifications, review approvals and exception review queues |
| P1 | Telemetry coverage | OpenTelemetry/agent integrations, sustained traffic benchmarks, log-source health and clock skew handling, detection tuning, investigated-alert correlation |
| P1 | API contracts | Complete versioned OpenAPI spec, public SDK, compatibility tests, idempotent external mutations and consistent problem responses |
| P2 | Governance | Shared dashboards, risk trend/MTTR reporting, custom controls/manual review evidence, audit export and tamper-evident retention |
| P2 | Deployment | Real hosted/private-runner parity, release signing, migration rollback strategy, upgrade channel, disaster recovery and operational SLOs |

Do not enable automatic repository edits, public scanning, or paid cloud execution merely to close a feature comparison. Those remain separate product and authorization decisions.
