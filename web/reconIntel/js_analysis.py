"""Pure-Python JavaScript analysis: endpoint extraction + secret scanning.

No external CLI tools. Uses `requests` and `beautifulsoup4` (already in the
image). Endpoint regex is LinkFinder-style; secret regexes are gitleaks-style.
"""

import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# LinkFinder-style regex for relative/absolute paths and URLs inside JS.
ENDPOINT_REGEX = re.compile(r"""
  (?:"|')                               # start quote
  (
    ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})  # full URL
    |
    ((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})    # relative path
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4})(?:[\?|#][^"|']{0,}|)) # path.ext
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|)) # api-ish path
  )
  (?:"|')                               # end quote
""", re.VERBOSE)

# Secret patterns: (name, regex, severity). Severity uses DiscoveredSecret ints.
SECRET_PATTERNS = [
    ('aws_access_key_id', re.compile(r'AKIA[0-9A-Z]{16}'), 4),
    ('aws_secret_access_key', re.compile(r'(?i)aws.{0,20}?(?:secret|key).{0,3}[=:"\']\s*([A-Za-z0-9/+=]{40})'), 4),
    ('google_api_key', re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 3),
    ('google_oauth', re.compile(r'ya29\.[0-9A-Za-z\-_]+'), 3),
    ('slack_token', re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,48}'), 4),
    ('slack_webhook', re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+'), 3),
    ('github_token', re.compile(r'gh[pousr]_[0-9A-Za-z]{36,}'), 4),
    ('stripe_key', re.compile(r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}'), 4),
    ('jwt', re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'), 2),
    ('private_key_header', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'), 4),
    ('generic_api_key', re.compile(r'(?i)(?:api[_-]?key|apikey|secret|token)["\']?\s*[:=]\s*["\']([0-9a-zA-Z\-_]{16,64})["\']'), 2),
    ('firebase_url', re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'), 2),
]

# Common API schema paths worth probing on a host.
API_SCHEMA_PATHS = [
    '/swagger.json', '/swagger/v1/swagger.json', '/openapi.json',
    '/api-docs', '/api/swagger.json', '/v2/api-docs', '/graphql',
]

DEFAULT_TIMEOUT = 10
MAX_JS_BYTES = 5 * 1024 * 1024  # don't slurp giant bundles


def _fetch(url, proxy=None, timeout=DEFAULT_TIMEOUT):
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    try:
        resp = requests.get(url, proxies=proxies, timeout=timeout, verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'},
                            stream=True)
        content = resp.raw.read(MAX_JS_BYTES, decode_content=True)
        return content.decode('utf-8', errors='ignore')
    except Exception:
        return None


def extract_js_urls(page_url, html):
    """Return absolute URLs of <script src> and inline scripts' host from HTML."""
    js_urls = []
    inline_blobs = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_urls.append(urljoin(page_url, src))
            elif script.string:
                inline_blobs.append(script.string)
    except Exception:
        pass
    return js_urls, inline_blobs


def extract_endpoints_from_js(js_text, base_url):
    """Return a set of absolute-ish endpoint strings found in JS text."""
    found = set()
    for match in ENDPOINT_REGEX.finditer(js_text):
        raw = match.group(1)
        if not raw or len(raw) < 3:
            continue
        # Skip obvious noise: file extensions we don't care about, mime types.
        if raw.startswith(('data:', 'javascript:', 'mailto:', 'tel:')):
            continue
        if raw.startswith(('http://', 'https://', '//')):
            found.add(raw if not raw.startswith('//') else 'https:' + raw)
        else:
            found.add(urljoin(base_url, raw))
    return found


def extract_secrets_from_text(text, source_url):
    """Return list of dicts {secret_type, severity, redacted_snippet, source_url}."""
    results = []
    seen = set()
    for name, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                'secret_type': name,
                'severity': severity,
                'redacted_snippet': _mask(value),
                'source_url': source_url,
            })
    return results


def _mask(value):
    """Mask a secret so it is safe to store/display: keep first 4 + last 2 chars."""
    value = value.strip()
    if len(value) <= 8:
        return value[0] + '*' * (len(value) - 1) if value else ''
    return f'{value[:4]}{"*" * min(len(value) - 6, 20)}{value[-2:]}'


def analyze_url(url, base_host, scope_checker=None, proxy=None):
    """Fetch one URL (HTML page or JS file), returning discovered endpoints and secrets.

    Returns (endpoints:set[str], secrets:list[dict]).
    """
    text = _fetch(url, proxy=proxy)
    if not text:
        return set(), []

    endpoints = set()
    secrets = []
    parsed = urlparse(url)
    is_js = parsed.path.endswith('.js')

    if is_js:
        endpoints |= extract_endpoints_from_js(text, url)
        secrets += extract_secrets_from_text(text, url)
    else:
        # HTML page: pull script srcs + inline scripts, analyze each.
        js_urls, inline_blobs = extract_js_urls(url, text)
        for blob in inline_blobs:
            endpoints |= extract_endpoints_from_js(blob, url)
            secrets += extract_secrets_from_text(blob, url)
        for js_url in js_urls:
            js_text = _fetch(js_url, proxy=proxy)
            if not js_text:
                continue
            endpoints |= extract_endpoints_from_js(js_text, js_url)
            secrets += extract_secrets_from_text(js_text, js_url)

    # Scope filter on host of each endpoint.
    if scope_checker:
        filtered = set()
        for ep in endpoints:
            host = urlparse(ep).netloc.split(':')[0]
            if host and scope_checker.is_out_of_scope(host):
                continue
            filtered.add(ep)
        endpoints = filtered

    return endpoints, secrets
