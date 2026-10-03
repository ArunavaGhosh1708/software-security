# Remediation guidance

Guidance works without AI credentials. The dashboard derives curated steps from the finding's engine, rule, location, available detected commit and dependency metadata. Stored findings receive these improvements on display without a rescan. Original reports and fingerprints remain unchanged.

Secret findings distinguish generic API credentials, private keys, AWS access credentials and GitHub personal access tokens, with a conservative fallback for other rules. Guidance includes owner confirmation, retirement through the issuing system, consumer updates, source cleanup and verification. It never inspects the redacted secret to guess its provider or tests credentials against external services. Public client identifiers and inert fixtures require review.

For real credentials, retirement precedes any coordinated history cleanup. Rewriting history is not automatic or always required; it can disrupt collaborators and does not remove every external copy. See [GitHub's sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

Dependency guidance uses scanner-reported installed and fixed versions, with explicit missing-fix handling. Curated coding guidance covers bundled ESLint and Checkstyle rules plus Ruff F401/F841. Other rules retain scanner instructions and identify the required location, verification and missing context. Exact patches are not invented from masked or insufficient evidence.

New runner reports use the shared secret catalog and engine-specific evidence limitations. Existing findings show corrected secret, dependency, coding, infrastructure and runtime limitations through the dashboard. These are recommended actions, not proof of a tested repair or credential revocation.
