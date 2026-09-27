"""Deterministic, rule-based finding triage. No LLM.

Produces a risk_score, a confidence, and a likely-false-positive flag for a
Vulnerability from signals already in the DB - severity, the importance of the
asset it sits on, auth/admin context, CVSS if present, and whether it looks
like scanner noise on a duplicate page.
"""

# Base weight per nuclei/reNgine severity int (-1=unknown..4=critical).
SEVERITY_WEIGHT = {
    -1: 5,   # unknown
    0: 10,   # info
    1: 25,   # low
    2: 50,   # medium
    3: 75,   # high
    4: 95,   # critical
}

IMPORTANT_ASSET_BONUS = 10
AUTH_CONTEXT_BONUS = 8
HAS_CVE_BONUS = 5

# Keywords in the URL/name that suggest sensitive/auth surface.
SENSITIVE_KEYWORDS = [
    'admin', 'login', 'auth', 'token', 'api', 'internal', 'debug',
    'config', 'backup', 'upload', 'password', 'oauth', 'sso',
]

# Template/type hints that are frequently informational noise.
LOW_VALUE_INFO_HINTS = [
    'ssl', 'tls', 'http-missing-security-headers', 'waf-detect',
    'tech-detect', 'favicon', 'metatag', 'robots', 'sitemap',
]


def score_vulnerability(vuln, is_on_duplicate_page=False):
    """Return dict {risk_score, confidence, is_likely_false_positive, rationale}.

    `vuln` is a startScan.models.Vulnerability. `is_on_duplicate_page` lets the
    caller pass in the dedup clustering result.
    """
    reasons = []
    severity = vuln.severity if vuln.severity is not None else -1
    score = SEVERITY_WEIGHT.get(severity, 5)
    reasons.append(f'base severity weight {score}')

    confidence = 60

    # Asset importance.
    if getattr(vuln.subdomain, 'is_important', False):
        score += IMPORTANT_ASSET_BONUS
        confidence += 10
        reasons.append('on an asset marked important')

    # Auth/sensitive context from URL or name.
    haystack = f'{vuln.http_url or ""} {vuln.name or ""} {vuln.template_id or ""}'.lower()
    if any(kw in haystack for kw in SENSITIVE_KEYWORDS):
        score += AUTH_CONTEXT_BONUS
        confidence += 5
        reasons.append('touches auth/sensitive surface')

    # CVSS, if present, nudges score toward its 0-100 equivalent.
    if getattr(vuln, 'cvss_score', None):
        cvss_pts = float(vuln.cvss_score) * 10
        score = (score + cvss_pts) / 2
        confidence += 10
        reasons.append(f'CVSS {vuln.cvss_score}')

    # Has a CVE => more likely real/actionable.
    try:
        if vuln.cve_ids.exists():
            score += HAS_CVE_BONUS
            confidence += 10
            reasons.append('has CVE id')
    except Exception:
        pass

    # False-positive heuristics.
    is_fp = False
    if severity <= 0 and any(hint in haystack for hint in LOW_VALUE_INFO_HINTS):
        is_fp = True
        confidence -= 10
        reasons.append('info-level detection matching common-noise template')
    if is_on_duplicate_page and severity <= 1:
        is_fp = True
        reasons.append('low/info finding on a duplicate page cluster')

    score = max(0.0, min(100.0, float(score)))
    confidence = max(0.0, min(100.0, float(confidence)))
    return {
        'risk_score': round(score, 1),
        'confidence': round(confidence, 1),
        'is_likely_false_positive': is_fp,
        'rationale': '; '.join(reasons),
    }
