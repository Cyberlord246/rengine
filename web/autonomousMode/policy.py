"""PolicyEngine: composes reNgine's EXISTING authorization mechanisms.

This module introduces no new authorization primitive. It is a thin adapter
over three things that already exist and already gate human-initiated scans:

  1. RBAC - rolepermissions.checkers.has_permission(user, PERM_INITATE_SCANS_SUBSCANS),
     the same function api/permissions.py:HasPermission uses for every scan/
     subscan API call.
  2. Scope - reNgine.utilities.SubdomainScopeChecker, the same class
     subdomain_discovery() and save_subdomain() already use to drop
     out-of-scope subdomains.
  3. Engine config - EngineType.tasks, the YAML-derived list of task types
     the operator enabled for this scan engine.

The only new concept is risk_level, which can only *remove* candidate action
types from what those three mechanisms already allow (see risk_levels.py) -
it can never add one.
"""

from rolepermissions.checkers import has_permission

from reNgine.definitions import PERM_INITATE_SCANS_SUBSCANS
from reNgine.utilities import SubdomainScopeChecker
from autonomousMode.risk_levels import (
    RISK_LEVEL_ALLOWED_ACTIONS,
    RISK_LEVEL_REQUIRES_APPROVAL,
)


class PolicyResult:
    def __init__(self, decision, checks, reason):
        self.decision = decision  # 'allowed' | 'blocked' | 'requires_approval'
        self.checks = checks
        self.reason = reason


class PolicyEngine:
    def __init__(self, assessment):
        self.assessment = assessment
        self.engine = assessment.engine
        self._scope_checker = SubdomainScopeChecker(assessment.cfg_out_of_scope_subdomains or [])

    def evaluate(self, action_type, subdomain=None):
        target = subdomain.name if subdomain else self.assessment.domain.name
        engine_tasks = self.engine.tasks or []
        allowed_at_risk = RISK_LEVEL_ALLOWED_ACTIONS.get(self.assessment.risk_level, set())
        requires_approval_at_risk = RISK_LEVEL_REQUIRES_APPROVAL.get(self.assessment.risk_level, set())

        checks = {
            'rbac': has_permission(self.assessment.initiated_by, PERM_INITATE_SCANS_SUBSCANS),
            'scope': not self._scope_checker.is_out_of_scope(target),
            'engine_enabled': action_type in engine_tasks,
            'risk_level': action_type in allowed_at_risk,
        }

        if not all(checks.values()):
            failed = [name for name, passed in checks.items() if not passed]
            return PolicyResult(
                'blocked', checks, f"Blocked by: {', '.join(failed)}")

        if action_type in requires_approval_at_risk:
            return PolicyResult(
                'requires_approval', checks,
                f'{action_type} requires manual approval at risk level '
                f'{self.assessment.get_risk_level_display()}')

        return PolicyResult(
            'allowed', checks, 'RBAC, scope and engine checks passed')
