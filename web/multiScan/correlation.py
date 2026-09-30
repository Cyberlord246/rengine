"""Cross-domain correlation + deduplication and endpoint classification runner
for a completed (or in-progress) assessment.

Reuses reconIntel.dedup for near-duplicate response collapsing and
multiScan.classification for the taxonomy mapping.
"""

from urllib.parse import urlparse

from django.utils import timezone

from startScan.models import EndPoint

from multiScan import classification as clsfy


def _scan_ids(assessment):
    return list(
        assessment.domain_runs.exclude(scan_history__isnull=True)
        .values_list('scan_history_id', flat=True)
    )


# An endpoint counts as an "actual response" only when it returned a real
# 2xx/3xx status. 404/403/401 and 5xx errors (and unprobed/0/null) are noise
# and are excluded from the report + classification.
def live_endpoints(qs):
    return qs.filter(http_status__gte=200, http_status__lt=400)


def classify_assessment_endpoints(assessment):
    """Walk every endpoint discovered across the assessment's child scans and
    write EndpointClassification rows. Idempotent (get_or_create)."""
    from multiScan.models import EndpointClassification

    scan_ids = _scan_ids(assessment)
    if not scan_ids:
        return 0

    created = 0
    endpoints = live_endpoints(
        EndPoint.objects.filter(scan_history_id__in=scan_ids)
    ).select_related('target_domain')
    for ep in endpoints.iterator():
        has_params = bool(urlparse(ep.http_url or '').query)
        cats = clsfy.classify_endpoint(ep.http_url, ep.matched_gf_patterns, has_params=has_params)
        for category, signals in cats:
            _, was_created = EndpointClassification.objects.get_or_create(
                assessment=assessment,
                endpoint=ep,
                category=category,
                defaults={
                    'domain': ep.target_domain,
                    'signals': signals,
                    'confidence': _confidence(signals),
                },
            )
            if was_created:
                created += 1
    return created


def _confidence(signals):
    # gf_pattern-backed classifications are higher confidence than keyword-only.
    if any(s.startswith('gf:') for s in signals):
        return 0.8
    if any(s.startswith('kw:') for s in signals):
        return 0.5
    return 0.3


def correlation_summary(assessment):
    """Return de-duplicated, cross-domain roll-ups keyed for the consolidated
    report: distinct hosts, technologies, and finding counts per domain."""
    from startScan.models import Subdomain, Vulnerability

    scan_ids = _scan_ids(assessment)
    summary = {'domains': [], 'totals': {}}

    distinct_hosts = set()
    distinct_techs = set()
    total_endpoints = 0
    total_vulns = 0

    for run in assessment.domain_runs.select_related('domain', 'scan_history'):
        scan = run.scan_history
        if not scan:
            summary['domains'].append({'domain': run.domain.name, 'status': run.status, 'subdomains': 0,
                                       'endpoints': 0, 'vulnerabilities': 0})
            continue
        subs = Subdomain.objects.filter(scan_history=scan)
        # Only endpoints with an actual 2xx/3xx response - exclude 404/403/errors.
        eps = live_endpoints(EndPoint.objects.filter(scan_history=scan))
        vulns = Vulnerability.objects.filter(scan_history=scan)
        for s in subs.values_list('name', flat=True):
            distinct_hosts.add(s)
        ep_count = eps.count()
        total_endpoints += ep_count
        total_vulns += vulns.count()
        summary['domains'].append({
            'domain': run.domain.name,
            'status': run.status,
            'subdomains': subs.count(),
            'live_endpoints': ep_count,
            'vulnerabilities': vulns.count(),
        })

    summary['totals'] = {
        'domains': assessment.domain_runs.count(),
        'distinct_hosts': len(distinct_hosts),
        'live_endpoints': total_endpoints,
        'vulnerabilities': total_vulns,
    }
    return summary
