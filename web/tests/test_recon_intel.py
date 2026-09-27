import os

os.environ.setdefault('RENGINE_SECRET_KEY', 'secret')
os.environ.setdefault('CELERY_ALWAYS_EAGER', 'True')

import yaml
from django.test import TestCase
from django.utils import timezone

from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

from reconIntel import dedup, js_analysis, param_discovery, scoring


class JsAnalysisTests(TestCase):
    def test_extracts_endpoints_from_js(self):
        js = '''
            var api = "/api/v1/users";
            fetch("https://api.example.com/orders");
            const p = './partials/login.html';
        '''
        endpoints = js_analysis.extract_endpoints_from_js(js, 'https://example.com/app.js')
        joined = ' '.join(endpoints)
        self.assertIn('/api/v1/users', joined)
        self.assertIn('api.example.com/orders', joined)

    def test_detects_and_masks_aws_key(self):
        text = 'const k = "AKIAIOSFODNN7EXAMPLE";'
        secrets = js_analysis.extract_secrets_from_text(text, 'https://example.com/app.js')
        types = [s['secret_type'] for s in secrets]
        self.assertIn('aws_access_key_id', types)
        aws = next(s for s in secrets if s['secret_type'] == 'aws_access_key_id')
        # The raw key must never appear verbatim in the stored snippet.
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', aws['redacted_snippet'])
        self.assertTrue(aws['redacted_snippet'].startswith('AKIA'))

    def test_mask_short_value(self):
        self.assertNotIn('secret', js_analysis._mask('secret')[1:])

    def test_generic_api_key_entropy_gate_rejects_noise(self):
        # Ordinary minified-JS assignment to a low-entropy identifier: dropped.
        noise = 'const token = "userProfileSettingsValue";'
        secrets = js_analysis.extract_secrets_from_text(noise, 'https://x.com/a.js')
        self.assertFalse([s for s in secrets if s['secret_type'] == 'generic_api_key'])

    def test_generic_api_key_keeps_high_entropy_value(self):
        real = 'apiKey: "aZ39Kd8Lm2Qp7Rt5Xy1Bv4Nw6Cs0Hf"'
        secrets = js_analysis.extract_secrets_from_text(real, 'https://x.com/a.js')
        self.assertTrue([s for s in secrets if s['secret_type'] == 'generic_api_key'])


class ParamDiscoveryTests(TestCase):
    def test_params_from_url(self):
        params = param_discovery.params_from_url('https://x.com/a?foo=1&bar=2')
        names = {n for n, t in params}
        self.assertEqual(names, {'foo', 'bar'})

    def test_params_from_url_no_query(self):
        self.assertEqual(param_discovery.params_from_url('https://x.com/a'), set())


class DedupTests(TestCase):
    def test_near_identical_pages_cluster_together(self):
        a = '<html><title>Login</title><body>Please sign in 12345</body></html>'
        b = '<html><title>Login</title><body>Please sign in 99999</body></html>'
        c = '<html><title>Dashboard</title><body>Totally different content here</body></html>'
        clusters = dedup.cluster([(1, a), (2, b), (3, c)])
        # a and b differ only by digits -> same cluster; c separate.
        cluster_of = {cid: idx for idx, cl in enumerate(clusters) for cid in cl}
        self.assertEqual(cluster_of[1], cluster_of[2])
        self.assertNotEqual(cluster_of[1], cluster_of[3])


class ScoringTests(TestCase):
    def setUp(self):
        self.engine = EngineType.objects.create(
            engine_name='ri_test', yaml_configuration=yaml.dump({'vulnerability_scan': {}}))
        self.domain = Domain.objects.create(name='example.com')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine, scan_status=2,
            start_scan_date=timezone.now())
        self.important_sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='admin.example.com',
            http_status=200, is_important=True)
        self.normal_sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='cdn.example.com',
            http_status=200)

    def _vuln(self, subdomain, severity, name, url):
        return Vulnerability.objects.create(
            scan_history=self.scan, subdomain=subdomain, target_domain=self.domain,
            name=name, severity=severity, http_url=url,
            discovered_date=timezone.now(), open_status=True)

    def test_critical_on_important_asset_outranks_info_noise(self):
        crit = self._vuln(self.important_sub, 4, 'Auth bypass', 'https://admin.example.com/login')
        info = self._vuln(self.normal_sub, 0, 'SSL info', 'https://cdn.example.com/')
        crit_score = scoring.score_vulnerability(crit)['risk_score']
        info_score = scoring.score_vulnerability(info)['risk_score']
        self.assertGreater(crit_score, info_score)

    def test_info_ssl_finding_flagged_false_positive(self):
        info = self._vuln(self.normal_sub, 0, 'TLS version detected', 'https://cdn.example.com/')
        result = scoring.score_vulnerability(info)
        self.assertTrue(result['is_likely_false_positive'])

    def test_duplicate_page_low_finding_flagged(self):
        low = self._vuln(self.normal_sub, 1, 'Some low finding', 'https://cdn.example.com/dup')
        result = scoring.score_vulnerability(low, is_on_duplicate_page=True)
        self.assertTrue(result['is_likely_false_positive'])
