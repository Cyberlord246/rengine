"""Pure-Python JavaScript analysis: endpoint extraction + secret scanning.

No external CLI tools. Uses `requests` and `beautifulsoup4` (already in the
image). Endpoint regex is LinkFinder-style; secret regexes are gitleaks-style.
"""

import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
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

# Endpoints that are static assets are noise for an attack-surface map: they
# are not testable app/API routes, and minified JS references thousands of
# them, which floods the endpoint table. Filter them out at the source.
STATIC_ENDPOINT_EXTENSIONS = {
    'js', 'mjs', 'css', 'map',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'avif', 'ico', 'bmp', 'tiff',
    'woff', 'woff2', 'ttf', 'eot', 'otf',
    'mp4', 'webm', 'mp3', 'wav', 'ogg', 'mov', 'avi',
    'pdf', 'zip', 'gz', 'tar', 'rar', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
}
# Path fragments that mark bundled/static/CDN asset URLs rather than routes.
ASSET_PATH_MARKERS = [
    '/_next/static/', '/static/', '/assets/', '/dims4/', '/fonts/',
    '/font/', '/images/', '/img/', '/media/', '/cdn-cgi/',
]
# Hard cap on endpoints a single js_analysis run will keep, so a pathological
# bundle can never flood the DB / UI.
DEFAULT_MAX_JS_ENDPOINTS = 300


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


NAMESPACE_HOSTS = {'www.w3.org', 'schemas.xmlsoap.org', 'www.opengis.net'}


def _clean_candidate(raw):
    """Strip JS-string escape artifacts; return None if the value is not a
    usable URL/path (contains escapes, whitespace, or markup)."""
    if not raw:
        return None
    # Trailing escape/quote debris from minified JS string literals.
    raw = raw.rstrip('\\"\' ')
    # Reject anything still carrying escape sequences or markup - these are
    # capture artifacts, not real endpoints.
    if any(tok in raw for tok in ('\\', '\\u', ' ', '\t', '\n', '<', '>', '{', '}', '`', '$')):
        return None
    return raw or None


def extract_endpoints_from_js(js_text, base_url):
    """Return a set of absolute-ish endpoint strings found in JS text."""
    found = set()
    for match in ENDPOINT_REGEX.finditer(js_text):
        raw = _clean_candidate(match.group(1))
        if not raw or len(raw) < 3:
            continue
        if raw.startswith(('data:', 'javascript:', 'mailto:', 'tel:', '#')):
            continue
        if raw.startswith(('http://', 'https://', '//')):
            url = raw if not raw.startswith('//') else 'https:' + raw
        else:
            url = urljoin(base_url, raw)
        # Drop XML/SVG namespace URLs - never real endpoints.
        if urlparse(url).netloc in NAMESPACE_HOSTS:
            continue
        found.add(url)
    return found


# Generic-pattern matches are only kept when the captured value looks like a
# real secret: long enough and high-entropy. Minified JS is full of
# api_key/token/secret assignments to ordinary identifiers, which is pure noise
# without this gate (gitleaks/trufflehog take the same entropy approach).
GENERIC_MIN_LENGTH = 24
GENERIC_MIN_ENTROPY = 3.5


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_secret(value):
    if len(value) < GENERIC_MIN_LENGTH:
        return False
    # Real API keys/tokens almost always mix letters and digits; camelCase JS
    # identifiers (the dominant noise source) are letters-only. Require both a
    # letter and a digit, plus high entropy, to keep only secret-shaped values.
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    if not (has_letter and has_digit):
        return False
    return _shannon_entropy(value) >= GENERIC_MIN_ENTROPY


def extract_secrets_from_text(text, source_url):
    """Return list of dicts {secret_type, severity, redacted_snippet, source_url}."""
    results = []
    seen = set()
    for name, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            # For the broad generic pattern, gate on the CAPTURED value
            # (group 1) with a length + entropy check to cut false positives.
            if name == 'generic_api_key':
                captured = match.group(1) if match.groups() else value
                if not _looks_like_secret(captured):
                    continue
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
        eps, secs = _analyze_js(url, text, proxy)
        endpoints |= eps
        secrets += secs
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
            eps, secs = _analyze_js(js_url, js_text, proxy)
            endpoints |= eps
            secrets += secs

    # Drop static assets / bundle URLs, then scope-filter on host.
    kept = set()
    for ep in endpoints:
        if is_noise_endpoint(ep):
            continue
        if scope_checker:
            host = urlparse(ep).netloc.split(':')[0]
            if host and scope_checker.is_out_of_scope(host):
                continue
        kept.add(ep)

    return kept, secrets


SOURCEMAP_COMMENT = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)')


def _analyze_js(js_url, js_text, proxy=None):
    """Analyze one JS file's text for endpoints + secrets, and also follow its
    source map (.map) if present - source maps embed original source and are a
    high-yield place for secrets."""
    endpoints = extract_endpoints_from_js(js_text, js_url)
    secrets = extract_secrets_from_text(js_text, js_url)

    # Locate the source map: explicit sourceMappingURL comment, else <js>.map.
    map_url = None
    m = SOURCEMAP_COMMENT.search(js_text[-2000:])  # comment is at file end
    if m:
        ref = m.group(1)
        if not ref.startswith('data:'):  # inline data-URI maps already in text
            map_url = urljoin(js_url, ref)
    else:
        map_url = js_url + '.map'

    if map_url:
        map_text = _fetch(map_url, proxy=proxy)
        if map_text and ('"sources"' in map_text or '"sourcesContent"' in map_text):
            # Scan the map's original source for secrets and endpoints.
            secrets += extract_secrets_from_text(map_text, map_url)
            endpoints |= extract_endpoints_from_js(map_text, js_url)
    return endpoints, secrets


def probe_liveness(urls, proxy=None, max_workers=20, timeout=8):
    """Concurrently probe URLs and return {url: http_status} for those that
    respond. Self-contained (does not touch reNgine's http_crawl dedup path)."""
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    headers = {'User-Agent': 'Mozilla/5.0 (reNgine reconIntel)'}

    def _probe(u):
        try:
            r = requests.head(u, timeout=timeout, verify=False, proxies=proxies,
                              headers=headers, allow_redirects=True)
            # Some servers reject HEAD - fall back to a lightweight GET.
            if r.status_code in (405, 400, 501):
                r = requests.get(u, timeout=timeout, verify=False, proxies=proxies,
                                 headers=headers, allow_redirects=True, stream=True)
            return u, r.status_code
        except Exception:
            return u, None

    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for u, status in pool.map(_probe, urls):
            if status is not None:
                results[u] = status
    return results


def is_noise_endpoint(url):
    """True if the URL is a static asset / bundle reference rather than a
    testable app or API route."""
    try:
        parsed = urlparse(url)
    except Exception:
        return True
    path = (parsed.path or '').lower()
    # Static file extension.
    if '.' in path.rsplit('/', 1)[-1]:
        ext = path.rsplit('.', 1)[-1]
        if ext in STATIC_ENDPOINT_EXTENSIONS:
            return True
    # Known static/bundle/CDN path markers.
    if any(marker in path for marker in ASSET_PATH_MARKERS):
        return True
    return False
