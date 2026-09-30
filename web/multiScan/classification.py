"""Deterministic endpoint classification into a manual-validation taxonomy.

No LLM, no exploitation - endpoints are only *categorized* as candidates for
a human to review. Heavily reuses reNgine's existing gf_pattern tags stored on
EndPoint.matched_gf_patterns, plus URL/keyword heuristics.
"""

# Category constants (also used as EndpointClassification.category choices).
CAT_AUTH = 'auth'
CAT_ACCESS_CONTROL = 'access_control'
CAT_INJECTION = 'injection'
CAT_XSS = 'xss'
CAT_SSRF = 'ssrf'
CAT_FILE = 'file_upload_download'
CAT_TRAVERSAL = 'path_traversal'
CAT_API = 'api'
CAT_INFO = 'info_exposure'
CAT_MISCONFIG = 'misconfig'
CAT_ADMIN = 'admin'
CAT_DEBUG = 'debug_dev'
CAT_CLOUD = 'cloud_storage'
CAT_REDIRECT = 'open_redirect'

CATEGORY_CHOICES = [
    (CAT_AUTH, 'Authentication/Authorization'),
    (CAT_ACCESS_CONTROL, 'Access control / IDOR candidate'),
    (CAT_INJECTION, 'Injection candidate'),
    (CAT_XSS, 'XSS candidate'),
    (CAT_SSRF, 'SSRF candidate'),
    (CAT_FILE, 'File upload/download'),
    (CAT_TRAVERSAL, 'Path traversal'),
    (CAT_API, 'API endpoint'),
    (CAT_INFO, 'Sensitive information exposure'),
    (CAT_MISCONFIG, 'Misconfiguration'),
    (CAT_ADMIN, 'Admin/management interface'),
    (CAT_DEBUG, 'Debug/development endpoint'),
    (CAT_CLOUD, 'Cloud/storage exposure'),
    (CAT_REDIRECT, 'Open redirect'),
]

# gf_pattern tag -> category (reNgine already tags endpoints with these).
GF_PATTERN_MAP = {
    'idor': CAT_ACCESS_CONTROL,
    'sqli': CAT_INJECTION,
    'ssti': CAT_INJECTION,
    'lfi': CAT_TRAVERSAL,
    'rce': CAT_INJECTION,
    'xss': CAT_XSS,
    'ssrf': CAT_SSRF,
    'redirect': CAT_REDIRECT,
    'interestingEXT': CAT_INFO,
    'interestingparams': CAT_API,
    'interestingsubs': CAT_INFO,
    'debug_logic': CAT_DEBUG,
}

# URL keyword -> category (substring match on the path, lowercased).
KEYWORD_MAP = [
    (('/api/', '/graphql', '/rest/', '/v1/', '/v2/', '.json', '/swagger', '/openapi'), CAT_API),
    (('login', 'signin', 'sign-in', 'oauth', 'auth', 'sso', 'token', 'session', 'logout', 'register'), CAT_AUTH),
    (('admin', 'manage', 'management', 'console', 'dashboard'), CAT_ADMIN),
    (('debug', '/dev', 'test', 'staging', 'trace', 'phpinfo', 'actuator'), CAT_DEBUG),
    (('.env', 'config', 'settings', '.git', 'backup', '.bak', 'wp-config'), CAT_MISCONFIG),
    (('upload', 'download', 'file', 'attachment', 'export', 'import'), CAT_FILE),
    (('s3', 'blob', 'storage', 'bucket', 'azure', 'gcs', 'cloudfront'), CAT_CLOUD),
    (('redirect', 'return', 'returnurl', 'next=', 'url=', 'callback'), CAT_REDIRECT),
    (('id=', 'uid=', 'user=', 'account=', 'profile'), CAT_ACCESS_CONTROL),
]


def classify_endpoint(http_url, matched_gf_patterns=None, has_params=False):
    """Return list of (category, signal) tuples for one endpoint.

    `matched_gf_patterns` is EndPoint.matched_gf_patterns (comma/space list).
    """
    results = {}

    # 1. gf_pattern tags (highest confidence - reNgine already matched them).
    if matched_gf_patterns:
        tags = [t.strip() for t in matched_gf_patterns.replace(',', ' ').split() if t.strip()]
        for tag in tags:
            cat = GF_PATTERN_MAP.get(tag)
            if cat:
                results.setdefault(cat, []).append(f'gf:{tag}')

    # 2. URL keyword heuristics.
    path = (http_url or '').lower()
    for keywords, cat in KEYWORD_MAP:
        for kw in keywords:
            if kw in path:
                results.setdefault(cat, []).append(f'kw:{kw}')
                break

    # 3. A parameterized endpoint with no other signal is at least an API/param candidate.
    if has_params and not results:
        results.setdefault(CAT_API, []).append('has_params')

    return [(cat, signals) for cat, signals in results.items()]
