"""Celery task entrypoints for the reconIntel intelligence layer.

Each task follows reNgine's RengineTask convention `(self, urls=[], ctx={},
description=None)` so it works both as a scan-engine pipeline step and as an
Autonomous Mode subscan action. All logic is pure Python (see the sibling
modules); tasks only orchestrate + persist.
"""

from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.common_func import get_http_urls, get_random_proxy
from reNgine.utilities import SubdomainScopeChecker
from startScan.models import EndPoint, Subdomain, Vulnerability

from reconIntel import dedup as dedup_mod
from reconIntel import js_analysis as js_mod
from reconIntel import origin_ip as origin_mod
from reconIntel import param_discovery as param_mod
from reconIntel import scoring as scoring_mod
from reconIntel.models import (
    DiscoveredSecret,
    FindingScore,
    HttpParameter,
    OriginIpCandidate,
)

logger = get_task_logger(__name__)


def _save_endpoint_urls(urls, ctx, source='js_analysis'):
    """Persist discovered endpoint URLs via reNgine's own save_endpoint so
    they flow through the normal dedup/correlation path. save_endpoint reads
    subscan_id from ctx (not a kwarg)."""
    from reNgine.tasks import save_endpoint  # local import avoids circularity
    created = 0
    for url in urls:
        endpoint, was_created = save_endpoint(url, ctx=ctx, crawl=False, source=source)
        if was_created:
            created += 1
    return created


@app.task(name='js_analysis', queue='reconintel_queue', base=RengineTask, bind=True)
def js_analysis(self, urls=[], ctx={}, description=None):
    """Extract endpoints and secrets from JavaScript / HTML pages."""
    scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains or [])
    proxy = get_random_proxy()
    domain_name = self.domain.name if self.domain else ''

    if not urls:
        urls = get_http_urls(is_alive=True, ctx=ctx) or []
    if not urls:
        urls = [s.http_url for s in Subdomain.objects.filter(scan_history=self.scan) if s.http_url]

    all_endpoints = set()
    total_secrets = 0
    for url in urls:
        endpoints, secrets = js_mod.analyze_url(url, domain_name, scope_checker, proxy)
        all_endpoints |= endpoints
        for secret in secrets:
            _, created = DiscoveredSecret.objects.get_or_create(
                scan_history=self.scan,
                secret_type=secret['secret_type'],
                redacted_snippet=secret['redacted_snippet'],
                source_url=secret['source_url'],
                defaults={
                    'subdomain': self.subdomain,
                    'severity': secret['severity'],
                    'discovered_date': timezone.now(),
                },
            )
            if created:
                total_secrets += 1

    if self.subscan_id:
        ctx = {**ctx, 'subscan_id': self.subscan_id}
    new_endpoints = _save_endpoint_urls(all_endpoints, ctx)
    self.notify(fields={
        'JS endpoints discovered': len(all_endpoints),
        'New endpoints saved': new_endpoints,
        'Secrets found': total_secrets,
    })
    return {'endpoints': len(all_endpoints), 'new_endpoints': new_endpoints, 'secrets': total_secrets}


@app.task(name='param_discovery', queue='reconintel_queue', base=RengineTask, bind=True)
def param_discovery(self, urls=[], ctx={}, description=None):
    """Passively discover request parameter names (Wayback + known endpoints)."""
    host = self.subdomain.name if self.subdomain else (self.domain.name if self.domain else None)
    if not host:
        return {'parameters': 0}

    params = set(param_mod.wayback_params(host))
    for endpoint in EndPoint.objects.filter(scan_history=self.scan):
        params |= param_mod.params_from_url(endpoint.http_url)

    saved = 0
    for name, ptype in params:
        _, created = HttpParameter.objects.get_or_create(
            scan_history=self.scan,
            endpoint=None,
            name=name[:500],
            param_type=ptype,
            defaults={'subdomain': self.subdomain, 'source': 'passive', 'discovered_date': timezone.now()},
        )
        if created:
            saved += 1
    self.notify(fields={'Parameters discovered': len(params), 'New parameters': saved})
    return {'parameters': len(params), 'new_parameters': saved}


@app.task(name='origin_ip_discovery', queue='reconintel_queue', base=RengineTask, bind=True)
def origin_ip_discovery(self, urls=[], ctx={}, description=None):
    """Find candidate origin IPs for the target domain (possibly behind CDN/WAF)."""
    if not self.domain:
        return {'candidates': 0}

    candidates = origin_mod.gather_candidates(self.domain.name)
    saved = 0
    for cand in candidates:
        _, created = OriginIpCandidate.objects.get_or_create(
            scan_history=self.scan,
            domain=self.domain,
            ip_address=cand['ip_address'],
            source=cand['source'],
            defaults={
                'confidence': cand['confidence'],
                'is_behind_cdn_bypass': cand['confidence'] >= 50,
                'discovered_date': timezone.now(),
            },
        )
        if created:
            saved += 1
    self.notify(fields={'Origin IP candidates': len(candidates), 'New candidates': saved})
    return {'candidates': len(candidates), 'new_candidates': saved}


@app.task(name='response_dedup', queue='reconintel_queue', base=RengineTask, bind=True)
def response_dedup(self, urls=[], ctx={}, description=None):
    """Cluster near-identical endpoints by response-title similarity."""
    endpoints = list(EndPoint.objects.filter(scan_history=self.scan).exclude(page_title__isnull=True))
    items = [(e.id, f'{e.page_title or ""} {e.webserver or ""}') for e in endpoints]
    clusters = dedup_mod.cluster(items) if items else []
    duplicate_count = sum(len(c) - 1 for c in clusters if len(c) > 1)
    self.notify(fields={
        'Endpoints analyzed': len(items),
        'Distinct clusters': len(clusters),
        'Near-duplicates collapsed': duplicate_count,
    })
    return {'clusters': len(clusters), 'duplicates': duplicate_count}


@app.task(name='finding_scoring', queue='reconintel_queue', base=RengineTask, bind=True)
def finding_scoring(self, urls=[], ctx={}, description=None):
    """Assign deterministic risk scores + false-positive flags to findings."""
    vulns = Vulnerability.objects.filter(scan_history=self.scan)

    # Endpoint ids that fall in multi-member (duplicate) clusters.
    endpoints = list(EndPoint.objects.filter(scan_history=self.scan).exclude(page_title__isnull=True))
    items = [(e.id, f'{e.page_title or ""} {e.webserver or ""}') for e in endpoints]
    clusters = dedup_mod.cluster(items) if items else []
    duplicate_endpoint_ids = set()
    for c in clusters:
        if len(c) > 1:
            duplicate_endpoint_ids.update(c[1:])

    scored = 0
    fp = 0
    for vuln in vulns:
        on_dup = bool(vuln.endpoint_id and vuln.endpoint_id in duplicate_endpoint_ids)
        result = scoring_mod.score_vulnerability(vuln, is_on_duplicate_page=on_dup)
        FindingScore.objects.update_or_create(
            vulnerability=vuln,
            defaults={
                'risk_score': result['risk_score'],
                'confidence': result['confidence'],
                'is_likely_false_positive': result['is_likely_false_positive'],
                'rationale': result['rationale'],
                'scored_at': timezone.now(),
            },
        )
        scored += 1
        if result['is_likely_false_positive']:
            fp += 1
    self.notify(fields={'Findings scored': scored, 'Likely false positives': fp})
    return {'scored': scored, 'false_positives': fp}
