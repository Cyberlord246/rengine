"""Passive HTTP parameter discovery. No active fuzzing, no arjun.

Mines parameter names from:
  - the Wayback Machine CDX API (historical URLs for the host)
  - query strings of endpoints already discovered in this scan
"""

from urllib.parse import parse_qs, urlparse

import requests

CDX_URL = 'http://web.archive.org/cdx/search/cdx'
DEFAULT_TIMEOUT = 20
MAX_CDX_ROWS = 5000


def params_from_url(url):
    """Return {(name, 'query')} extracted from a URL's query string."""
    try:
        qs = urlparse(url).query
        if not qs:
            return set()
        return {(name, 'query') for name in parse_qs(qs).keys()}
    except Exception:
        return set()


def wayback_params(host, timeout=DEFAULT_TIMEOUT):
    """Query the Wayback CDX API for URLs on `host`, return {(name, 'query')}.

    Returns an empty set on any network/parse error - callers degrade gracefully.
    """
    params = set()
    query = {
        'url': f'{host}/*',
        'output': 'json',
        'fl': 'original',
        'collapse': 'urlkey',
        'limit': MAX_CDX_ROWS,
    }
    try:
        resp = requests.get(CDX_URL, params=query, timeout=timeout,
                            headers={'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'})
        if resp.status_code != 200:
            return params
        rows = resp.json()
    except Exception:
        return params

    # First row is the header ['original'] when fl=original.
    for row in rows[1:] if rows else []:
        url = row[0] if isinstance(row, list) else row
        params |= params_from_url(url)
    return params
