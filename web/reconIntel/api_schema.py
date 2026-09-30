"""Discover and parse API schemas (Swagger / OpenAPI / GraphQL) to turn a host
into concrete, documented endpoints and parameters. Pure Python + requests.
"""

import json
from urllib.parse import urljoin, urlparse

import requests

DEFAULT_TIMEOUT = 12

SCHEMA_PATHS = [
    '/swagger.json', '/swagger/v1/swagger.json', '/openapi.json',
    '/v2/api-docs', '/v3/api-docs', '/api/swagger.json', '/api-docs',
    '/api/openapi.json', '/docs/openapi.json',
]
GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql']

# Minimal GraphQL introspection query (often disabled in prod - best effort).
_INTROSPECTION = {
    'query': '{__schema{queryType{name} mutationType{name} '
             'types{name fields{name}}}}'
}


def _get(url, proxy=None):
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False, proxies=proxies,
                         headers={'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'})
        if r.status_code == 200 and r.content:
            return r
    except Exception:
        pass
    return None


def parse_openapi(doc, base_url):
    """Return (endpoint_urls:set, params:list[(name, where)]) from an OpenAPI/Swagger dict."""
    endpoints = set()
    params = []
    paths = doc.get('paths') or {}
    if not isinstance(paths, dict):
        return endpoints, params
    for path, methods in paths.items():
        if not isinstance(path, str):
            continue
        endpoints.add(urljoin(base_url, path))
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            for p in op.get('parameters', []) or []:
                if isinstance(p, dict) and p.get('name'):
                    where = p.get('in', 'query')
                    params.append((p['name'], 'query' if where in ('query', 'path') else 'body'))
    return endpoints, params


def discover(base_url, proxy=None):
    """Probe schema paths on the host of base_url. Returns dict with
    'endpoints' (set) and 'params' (list of (name, type))."""
    parsed = urlparse(base_url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    endpoints = set()
    params = []

    for path in SCHEMA_PATHS:
        resp = _get(urljoin(origin, path), proxy=proxy)
        if not resp:
            continue
        try:
            doc = resp.json()
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(doc, dict) and ('paths' in doc or 'swagger' in doc or 'openapi' in doc):
            eps, ps = parse_openapi(doc, origin)
            endpoints |= eps
            params += ps

    # GraphQL: record the endpoint and attempt introspection for type/field names.
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    for path in GRAPHQL_PATHS:
        gql = urljoin(origin, path)
        try:
            r = requests.post(gql, json=_INTROSPECTION, timeout=DEFAULT_TIMEOUT, verify=False,
                              proxies=proxies, headers={'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'})
        except Exception:
            continue
        if r.status_code == 200 and '__schema' in (r.text or ''):
            endpoints.add(gql)  # confirmed, introspective GraphQL endpoint

    return {'endpoints': endpoints, 'params': params}
