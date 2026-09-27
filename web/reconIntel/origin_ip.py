"""Origin-IP discovery: find candidate real IPs for a host that may sit
behind a CDN/WAF. Pure Python + free HTTP sources; favicon mmh3 matching is
optional (skipped if `mmh3` is not installed).
"""

import socket
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 15

# IP ranges/keywords that indicate a CDN edge rather than an origin.
CDN_HINT_KEYWORDS = ['cloudflare', 'akamai', 'fastly', 'incapsula', 'sucuri', 'cloudfront']


def resolve_dns(host):
    """Return the set of A-record IPs the host currently resolves to."""
    ips = set()
    try:
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            if ':' not in ip:  # IPv4 only for now
                ips.add(ip)
    except Exception:
        pass
    return ips


def crtsh_related_hosts(domain, timeout=DEFAULT_TIMEOUT):
    """Query crt.sh certificate transparency for names under `domain`.

    Returns a set of hostnames (which callers can resolve to find IPs that a
    CDN-fronted apex may not advertise).
    """
    hosts = set()
    try:
        resp = requests.get(
            f'https://crt.sh/?q=%25.{domain}&output=json',
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'},
        )
        if resp.status_code != 200:
            return hosts
        for entry in resp.json():
            name = entry.get('common_name') or ''
            for n in [name] + (entry.get('name_value') or '').split('\n'):
                n = n.strip().lstrip('*.').lower()
                if n and domain in n:
                    hosts.add(n)
    except Exception:
        pass
    return hosts


def favicon_hash(url, timeout=DEFAULT_TIMEOUT):
    """Return the Shodan-style mmh3 favicon hash, or None if mmh3 unavailable
    or the favicon can't be fetched."""
    try:
        import mmh3  # optional dependency
    except ImportError:
        return None
    import base64
    try:
        parsed = urlparse(url)
        fav_url = f'{parsed.scheme}://{parsed.netloc}/favicon.ico'
        resp = requests.get(fav_url, timeout=timeout, verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'})
        if resp.status_code != 200 or not resp.content:
            return None
        b64 = base64.encodebytes(resp.content)
        return mmh3.hash(b64)
    except Exception:
        return None


def gather_candidates(domain_name):
    """Return a list of dicts {ip_address, source, confidence} for a domain.

    Deterministic and network-only; every source degrades to nothing on error.
    """
    candidates = {}

    # 1. Direct DNS (the advertised IP - low origin-confidence, may be CDN).
    for ip in resolve_dns(domain_name):
        candidates.setdefault(ip, {'ip_address': ip, 'source': 'dns', 'confidence': 20})

    # 2. Resolve cert-transparency-discovered subdomains; an IP that appears
    #    for a non-www host but not for the fronted apex is a better origin bet.
    apex_ips = set(candidates.keys())
    related = crtsh_related_hosts(domain_name)
    for host in list(related)[:100]:  # cap resolves
        for ip in resolve_dns(host):
            if ip in candidates:
                continue
            conf = 55 if ip not in apex_ips else 25
            candidates[ip] = {'ip_address': ip, 'source': 'crt_sh', 'confidence': conf}

    return list(candidates.values())
