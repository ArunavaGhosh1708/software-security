"""Curated platform-owned guidance; never reads detected secret values."""
import json
from pathlib import Path

CATALOG=json.loads((Path(__file__).resolve().parents[1]/'rules/remediation.json').read_text(encoding='utf-8'))

def secret_remediation(rule,path,line):
    key='github-pat' if rule.startswith('github-pat') else rule
    entry=CATALOG['secrets'].get(key,CATALOG['secrets']['default'])
    return f"{entry['summary']} Review {path}:{line}. "+' '.join(entry['steps'])+' Verification: '+entry['verification']

def evidence_limitation(engine,category):
    if engine=='gitleaks':return 'Secret-pattern match only. Credential validity, issuer permissions, and misuse have not been checked; public identifiers and inert fixtures require review.'
    if engine=='trivy':return 'Scanner advisory or configuration evidence. Applicability and application reachability require review; successful exploitation has not been established.'
    if engine=='dast':return 'Runtime scanner observation. Review the endpoint and authentication context; successful exploitation has not been established.'
    if engine=='lint' or category=='quality':return 'Analyzer or quality diagnostic. This does not demonstrate a security exploit.'
    return 'Pattern-based evidence. Verify input provenance and relevant controls; no exploit is proven.'
