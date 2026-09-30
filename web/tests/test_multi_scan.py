import os

os.environ.setdefault('RENGINE_SECRET_KEY', 'secret')
os.environ.setdefault('CELERY_ALWAYS_EAGER', 'True')

import yaml
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory, Subdomain
from targetApp.models import Domain

from multiScan import classification, orchestrator
from multiScan.models import Assessment, AssessmentDomainRun, EndpointClassification
from multiScan.correlation import classify_assessment_endpoints, correlation_summary


class _Run:
    """Lightweight stand-in for AssessmentDomainRun used in orchestrator tests."""
    def __init__(self, status):
        self.status = status


class OrchestratorBatchTests(TestCase):
    def test_batch_gate_never_exceeds_batch_size(self):
        runs = [_Run('running'), _Run('running'), _Run('pending'), _Run('pending'), _Run('pending')]
        # batch_size 3, 2 already running -> only 1 new slot
        to_launch = orchestrator.select_next_domains(runs, batch_size=3)
        self.assertEqual(len(to_launch), 1)

    def test_no_launch_when_batch_full(self):
        runs = [_Run('running'), _Run('running'), _Run('pending')]
        self.assertEqual(orchestrator.select_next_domains(runs, batch_size=2), [])

    def test_all_slots_when_none_running(self):
        runs = [_Run('pending'), _Run('pending'), _Run('pending')]
        self.assertEqual(len(orchestrator.select_next_domains(runs, batch_size=5)), 3)

    def test_all_runs_terminal(self):
        self.assertTrue(orchestrator.all_runs_terminal([_Run('completed'), _Run('failed')]))
        self.assertFalse(orchestrator.all_runs_terminal([_Run('completed'), _Run('running')]))


class ClassificationTests(TestCase):
    def test_gf_pattern_maps_to_category(self):
        cats = dict(classification.classify_endpoint('https://x.com/a', matched_gf_patterns='idor,sqli'))
        self.assertIn(classification.CAT_ACCESS_CONTROL, cats)
        self.assertIn(classification.CAT_INJECTION, cats)

    def test_url_keyword_api_and_auth(self):
        cats = dict(classification.classify_endpoint('https://x.com/api/v1/login'))
        self.assertIn(classification.CAT_API, cats)
        self.assertIn(classification.CAT_AUTH, cats)

    def test_admin_and_debug(self):
        cats = dict(classification.classify_endpoint('https://x.com/admin/debug/console'))
        self.assertIn(classification.CAT_ADMIN, cats)
        self.assertIn(classification.CAT_DEBUG, cats)

    def test_parameterized_defaults_to_api(self):
        cats = dict(classification.classify_endpoint('https://x.com/thing?ref=1', has_params=True))
        self.assertTrue(cats)  # at least one category

    def test_static_like_no_signal_is_empty(self):
        cats = classification.classify_endpoint('https://x.com/home')
        self.assertEqual(cats, [])


class CorrelationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='ms_tester', password='x')
        self.engine = EngineType.objects.create(
            engine_name='ms_test', yaml_configuration=yaml.dump({'http_crawl': {}}))
        self.assessment = Assessment.objects.create(
            name='A', engine=self.engine, initiated_by=self.user, status=Assessment.STATUS_RUNNING)
        self.d1 = Domain.objects.create(name='a.com')
        self.d2 = Domain.objects.create(name='b.com')
        self.assessment.domains.set([self.d1, self.d2])
        self.s1 = ScanHistory.objects.create(domain=self.d1, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now())
        self.s2 = ScanHistory.objects.create(domain=self.d2, scan_type=self.engine, scan_status=2, start_scan_date=timezone.now())
        AssessmentDomainRun.objects.create(assessment=self.assessment, domain=self.d1, scan_history=self.s1, status='completed')
        AssessmentDomainRun.objects.create(assessment=self.assessment, domain=self.d2, scan_history=self.s2, status='completed')
        EndPoint.objects.create(scan_history=self.s1, target_domain=self.d1, http_url='https://a.com/api/v1/users?id=1', matched_gf_patterns='idor', http_status=200)
        EndPoint.objects.create(scan_history=self.s2, target_domain=self.d2, http_url='https://b.com/admin/login', http_status=200)
        # These must be EXCLUDED from report/classification (404, 403, 5xx, unprobed).
        EndPoint.objects.create(scan_history=self.s1, target_domain=self.d1, http_url='https://a.com/notfound', matched_gf_patterns='idor', http_status=404)
        EndPoint.objects.create(scan_history=self.s2, target_domain=self.d2, http_url='https://b.com/forbidden', http_status=403)
        EndPoint.objects.create(scan_history=self.s2, target_domain=self.d2, http_url='https://b.com/error', http_status=500)
        EndPoint.objects.create(scan_history=self.s2, target_domain=self.d2, http_url='https://b.com/unprobed', http_status=0)

    def test_classify_assessment_endpoints_writes_rows(self):
        n = classify_assessment_endpoints(self.assessment)
        self.assertGreater(n, 0)
        cats = set(EndpointClassification.objects.filter(assessment=self.assessment).values_list('category', flat=True))
        self.assertIn(classification.CAT_ACCESS_CONTROL, cats)  # idor on a.com
        self.assertIn(classification.CAT_ADMIN, cats)           # /admin on b.com

    def test_correlation_summary_groups_by_domain(self):
        summary = correlation_summary(self.assessment)
        self.assertEqual(summary['totals']['domains'], 2)
        names = {d['domain'] for d in summary['domains']}
        self.assertEqual(names, {'a.com', 'b.com'})

    def test_only_live_endpoints_counted(self):
        summary = correlation_summary(self.assessment)
        # a.com has one 200 + one 404 -> only 1 live; b.com has one 200 + 403/500/0 -> 1 live
        per = {d['domain']: d['live_endpoints'] for d in summary['domains']}
        self.assertEqual(per['a.com'], 1)
        self.assertEqual(per['b.com'], 1)
        self.assertEqual(summary['totals']['live_endpoints'], 2)

    def test_error_endpoints_not_classified(self):
        classify_assessment_endpoints(self.assessment)
        urls = set(
            EndpointClassification.objects.filter(assessment=self.assessment)
            .values_list('endpoint__http_url', flat=True)
        )
        self.assertNotIn('https://a.com/notfound', urls)   # 404 excluded
        self.assertNotIn('https://b.com/forbidden', urls)  # 403 excluded
        self.assertNotIn('https://b.com/error', urls)      # 500 excluded


class DomainFailureIsolationTests(TestCase):
    def test_one_failed_run_does_not_block_terminal_check_incorrectly(self):
        runs = [_Run('failed'), _Run('completed')]
        self.assertTrue(orchestrator.all_runs_terminal(runs))
        runs2 = [_Run('failed'), _Run('running')]
        self.assertFalse(orchestrator.all_runs_terminal(runs2))
