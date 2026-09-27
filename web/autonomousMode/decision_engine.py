"""Deterministic, rule-based "what should we do next" scorer.

No LLM call happens here - every score is computed from plain Django ORM
queries against data reNgine's normal task pipeline already writes
(Subdomain, EndPoint, Vulnerability, SubScan). This keeps the autonomous
loop reproducible, free to run, and easy to unit test.
"""

from django.utils import timezone

from startScan.models import EndPoint, Subdomain, Vulnerability
from autonomousMode.models import AssessmentDecision
from autonomousMode.risk_levels import KNOWN_SUBSCAN_ACTIONS

# Action types the decision engine will ever propose per-subdomain. Domain-
# level steps (subdomain_discovery, osint) already ran once as part of the
# initial initiate_scan() bootstrap and are not re-proposed here.
SUBDOMAIN_LEVEL_ACTIONS = [
    'screenshot',
    'waf_detection',
    'port_scan',
    'fetch_url',
    'dir_file_fuzz',
    'vulnerability_scan',
]
assert set(SUBDOMAIN_LEVEL_ACTIONS) <= KNOWN_SUBSCAN_ACTIONS

# Technology names (lowercase substring match) considered high value enough
# to bump priority - kept intentionally small and generic.
HIGH_VALUE_TECH_HINTS = [
    'wordpress', 'jenkins', 'php', 'drupal', 'joomla', 'jira', 'confluence',
    'gitlab', 'tomcat', 'grafana', 'kibana', 'elasticsearch',
]

NEW_ASSET_ALIVE_WEIGHT = 3
IMPORTANT_OR_HIGH_VALUE_TECH_WEIGHT = 2
ENDPOINT_GROWTH_WEIGHT = 2
UNVALIDATED_FINDING_WEIGHT = 4

FAILURE_STREAK_LENGTH = 3


def _is_alive(subdomain):
    return bool(subdomain.http_status and 0 < subdomain.http_status < 500 and subdomain.http_status != 404)


def _has_high_value_tech(subdomain):
    names = [t.name.lower() for t in subdomain.technologies.all()]
    return any(hint in name for name in names for hint in HIGH_VALUE_TECH_HINTS)


def _already_attempted(assessment, subdomain, action_type):
    return AssessmentDecision.objects.filter(
        assessment=assessment,
        subdomain=subdomain,
        action_type=action_type,
        status__in=[
            AssessmentDecision.STATUS_DISPATCHED,
            AssessmentDecision.STATUS_COMPLETED,
            AssessmentDecision.STATUS_PENDING,
        ],
    ).exists()


def _action_type_has_failure_streak(assessment, action_type):
    recent = list(
        AssessmentDecision.objects
        .filter(assessment=assessment, action_type=action_type)
        .exclude(action_result_status__isnull=True)
        .order_by('-id')[:FAILURE_STREAK_LENGTH]
    )
    if len(recent) < FAILURE_STREAK_LENGTH:
        return False
    return all(d.action_result_status == AssessmentDecision.STATUS_FAILED for d in recent) or all(
        d.status == AssessmentDecision.STATUS_FAILED for d in recent
    )


def _score_candidate(assessment, subdomain, action_type):
    score = 0
    reasons = []

    if subdomain.discovered_date and assessment.started_at and subdomain.discovered_date >= assessment.started_at:
        if _is_alive(subdomain):
            score += NEW_ASSET_ALIVE_WEIGHT
            reasons.append('newly discovered live asset')

    if subdomain.is_important or _has_high_value_tech(subdomain):
        score += IMPORTANT_OR_HIGH_VALUE_TECH_WEIGHT
        reasons.append('marked important or running high-value technology')

    if action_type in ('dir_file_fuzz', 'vulnerability_scan'):
        endpoint_count = EndPoint.objects.filter(subdomain=subdomain).count()
        if endpoint_count > 0:
            score += ENDPOINT_GROWTH_WEIGHT
            reasons.append(f'{endpoint_count} endpoint(s) discovered on this asset')

    if action_type == 'vulnerability_scan':
        if Vulnerability.objects.filter(subdomain=subdomain, open_status=True).exists():
            score += UNVALIDATED_FINDING_WEIGHT
            reasons.append('has open findings that warrant (re)validation')

    if not _is_alive(subdomain) and action_type != 'waf_detection':
        score = 0
        reasons = ['asset not alive']

    return score, reasons


def next_candidates(assessment, limit=None):
    """Return up to `limit` scored (action_type, subdomain, score, reason, expected_outcome)
    candidates, highest score first, excluding anything already attempted or
    whose action_type is on a failure streak."""
    if not assessment.scan_history:
        return []

    limit = limit or assessment.actions_per_tick
    subdomains = Subdomain.objects.filter(scan_history=assessment.scan_history)

    eligible_action_types = [
        a for a in SUBDOMAIN_LEVEL_ACTIONS
        if not _action_type_has_failure_streak(assessment, a)
    ]

    scored = []
    for subdomain in subdomains:
        for action_type in eligible_action_types:
            if _already_attempted(assessment, subdomain, action_type):
                continue
            score, reasons = _score_candidate(assessment, subdomain, action_type)
            if score <= 0:
                continue
            scored.append({
                'action_type': action_type,
                'subdomain': subdomain,
                'score': score,
                'reason': '; '.join(reasons) or 'baseline priority',
                'expected_outcome': _expected_outcome(action_type),
            })

    scored.sort(key=lambda c: c['score'], reverse=True)
    return scored[:limit]


def _expected_outcome(action_type):
    return {
        'screenshot': 'Capture current visual state of the asset',
        'waf_detection': 'Confirm whether a WAF is in front of this asset',
        'port_scan': 'Identify additional open ports/services on this asset',
        'fetch_url': 'Discover live URLs/endpoints on this asset',
        'dir_file_fuzz': 'Uncover additional directories/files on this asset',
        'vulnerability_scan': 'Identify or validate vulnerabilities on this asset',
    }.get(action_type, 'Gather additional information about this asset')
