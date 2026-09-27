import os

os.environ.setdefault('RENGINE_SECRET_KEY', 'secret')
os.environ.setdefault('CELERY_ALWAYS_EAGER', 'True')

import yaml
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

from autonomousMode.decision_engine import next_candidates
from autonomousMode.models import AssessmentDecision, AutonomousAssessment
from autonomousMode.policy import PolicyEngine
from autonomousMode.tasks import evaluate_stop_conditions


class AutonomousModeTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='autonomous_tester', password='x')

        self.yaml_configuration = {
            'subdomain_discovery': {},
            'port_scan': {},
            'fetch_url': {},
            'vulnerability_scan': {},
            'screenshot': {},
        }
        self.engine = EngineType.objects.create(
            engine_name='autonomous_test_engine',
            yaml_configuration=yaml.dump(self.yaml_configuration),
        )
        self.domain = Domain.objects.create(name='example.com')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,  # SUCCESS_TASK
            start_scan_date=timezone.now(),
        )
        self.assessment = AutonomousAssessment.objects.create(
            domain=self.domain,
            engine=self.engine,
            scan_history=self.scan,
            mode=AutonomousAssessment.MODE_AUTONOMOUS,
            risk_level=AutonomousAssessment.RISK_STANDARD,
            status=AutonomousAssessment.STATUS_RUNNING,
            initiated_by=self.user,
            started_at=timezone.now(),
        )

    def _grant_rbac(self):
        from rolepermissions.roles import assign_role
        assign_role(self.user, 'sys_admin')

    # -- PolicyEngine --------------------------------------------------

    def test_policy_blocks_without_rbac(self):
        result = PolicyEngine(self.assessment).evaluate('port_scan')
        self.assertEqual(result.decision, 'blocked')
        self.assertFalse(result.checks['rbac'])

    def test_policy_blocks_action_not_in_engine(self):
        self._grant_rbac()
        result = PolicyEngine(self.assessment).evaluate('dir_file_fuzz')
        self.assertEqual(result.decision, 'blocked')
        self.assertFalse(result.checks['engine_enabled'])
        self.assertTrue(result.checks['rbac'])

    def test_policy_blocks_out_of_scope_subdomain(self):
        self._grant_rbac()
        self.assessment.cfg_out_of_scope_subdomains = ['admin.example.com']
        self.assessment.save()
        subdomain = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='admin.example.com')
        result = PolicyEngine(self.assessment).evaluate('port_scan', subdomain=subdomain)
        self.assertEqual(result.decision, 'blocked')
        self.assertFalse(result.checks['scope'])

    def test_safe_risk_level_blocks_active_scan_even_if_engine_enables_it(self):
        self._grant_rbac()
        self.assessment.risk_level = AutonomousAssessment.RISK_SAFE
        self.assessment.save()
        # 'port_scan' IS enabled by the engine, but SAFE risk level must still block it.
        result = PolicyEngine(self.assessment).evaluate('port_scan')
        self.assertEqual(result.decision, 'blocked')
        self.assertFalse(result.checks['risk_level'])

    def test_controlled_risk_level_requires_approval_for_vuln_scan(self):
        self._grant_rbac()
        self.assessment.risk_level = AutonomousAssessment.RISK_CONTROLLED
        self.assessment.save()
        result = PolicyEngine(self.assessment).evaluate('vulnerability_scan')
        self.assertEqual(result.decision, 'requires_approval')

    def test_standard_risk_level_allows_enabled_active_scan(self):
        self._grant_rbac()
        result = PolicyEngine(self.assessment).evaluate('port_scan')
        self.assertEqual(result.decision, 'allowed')

    # -- Stop conditions -------------------------------------------------

    def test_stops_on_action_budget(self):
        self.assessment.max_actions = 1
        self.assessment.actions_taken_count = 1
        self.assessment.save()
        result = evaluate_stop_conditions(self.assessment)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], AutonomousAssessment.STATUS_COMPLETED)

    def test_stops_on_consecutive_failures(self):
        self.assessment.consecutive_failures = self.assessment.failure_threshold
        self.assessment.save()
        result = evaluate_stop_conditions(self.assessment)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], AutonomousAssessment.STATUS_FAILED)

    def test_stops_when_domain_itself_out_of_scope(self):
        self.assessment.cfg_out_of_scope_subdomains = ['example.com']
        self.assessment.save()
        result = evaluate_stop_conditions(self.assessment)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], AutonomousAssessment.STATUS_STOPPED)

    def test_does_not_stop_while_actions_still_outstanding(self):
        subdomain = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='www.example.com',
            http_status=200)
        AssessmentDecision.objects.create(
            assessment=self.assessment, sequence=1, subdomain=subdomain,
            action_type='port_scan', status=AssessmentDecision.STATUS_DISPATCHED,
        )
        result = evaluate_stop_conditions(self.assessment)
        self.assertIsNone(result)

    # -- Decision engine ---------------------------------------------------

    def test_candidate_dedup_skips_already_attempted(self):
        subdomain = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='api.example.com',
            http_status=200)
        AssessmentDecision.objects.create(
            assessment=self.assessment, sequence=1, subdomain=subdomain,
            action_type='port_scan', status=AssessmentDecision.STATUS_COMPLETED,
        )
        candidates = next_candidates(self.assessment, limit=10)
        types_for_subdomain = [c['action_type'] for c in candidates if c['subdomain'] == subdomain]
        self.assertNotIn('port_scan', types_for_subdomain)

    def test_unvalidated_finding_boosts_vulnerability_scan_score(self):
        subdomain = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name='vuln.example.com',
            http_status=200)
        Vulnerability.objects.create(
            scan_history=self.scan, subdomain=subdomain, target_domain=self.domain,
            name='Test finding', severity=2, http_url='https://vuln.example.com/',
            discovered_date=timezone.now(), open_status=True,
        )
        candidates = next_candidates(self.assessment, limit=10)
        vuln_candidates = [c for c in candidates if c['subdomain'] == subdomain and c['action_type'] == 'vulnerability_scan']
        self.assertTrue(vuln_candidates)
        self.assertGreaterEqual(vuln_candidates[0]['score'], 4)
