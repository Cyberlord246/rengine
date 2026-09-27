"""Entry points used by both the page view (startScan/views.py) and the API
views (api/views.py) to control an AutonomousAssessment. Kept separate from
tasks.py so neither the web request path nor the Celery task path has to
import the other's module for these operations.
"""

from django.utils import timezone

from reNgine.celery import app
from reNgine.definitions import ABORTED_TASK

from autonomousMode.models import AssessmentDecision, AutonomousAssessment


def start_assessment(domain, engine, mode, risk_level, user, **budgets):
    """Create and immediately start ticking a new AutonomousAssessment.

    `budgets` may include any of: max_runtime_minutes, max_actions,
    actions_per_tick, tick_interval_seconds, out_of_scope_subdomains,
    imported_subdomains, starting_point_path, excluded_paths.
    """
    assessment = AutonomousAssessment(
        domain=domain,
        engine=engine,
        mode=mode,
        risk_level=risk_level,
        initiated_by=user,
        status=AutonomousAssessment.STATUS_RUNNING,
        started_at=timezone.now(),
        next_tick_eta=timezone.now(),
    )
    for field in ('max_runtime_minutes', 'max_actions', 'actions_per_tick', 'tick_interval_seconds'):
        if field in budgets and budgets[field]:
            setattr(assessment, field, budgets[field])

    assessment.cfg_out_of_scope_subdomains = budgets.get('out_of_scope_subdomains') or []
    assessment.cfg_imported_subdomains = budgets.get('imported_subdomains') or []
    assessment.cfg_starting_point_path = budgets.get('starting_point_path') or ''
    assessment.cfg_excluded_paths = budgets.get('excluded_paths') or []
    assessment.save()

    # Imported here (not at module top) to avoid a circular import between
    # autonomousMode.tasks (which imports this module for reconciliation
    # helpers) and autonomousMode.services.
    from autonomousMode.tasks import autonomous_loop_tick
    autonomous_loop_tick.delay(assessment.id)
    return assessment


def pause_assessment(assessment):
    assessment.status = AutonomousAssessment.STATUS_PAUSED
    assessment.save(update_fields=['status', 'updated_at'])
    return assessment


def resume_assessment(assessment):
    assessment.status = AutonomousAssessment.STATUS_RUNNING
    assessment.next_tick_eta = timezone.now()
    assessment.save(update_fields=['status', 'next_tick_eta', 'updated_at'])

    from autonomousMode.tasks import autonomous_loop_tick
    autonomous_loop_tick.delay(assessment.id)
    return assessment


def stop_assessment(assessment, reason='Stopped by user'):
    in_flight = assessment.decisions.filter(status=AssessmentDecision.STATUS_DISPATCHED)
    for decision in in_flight:
        if decision.subscan:
            for task_id in decision.subscan.celery_ids:
                app.control.revoke(task_id, terminate=True, signal='SIGKILL')
            decision.subscan.status = ABORTED_TASK
            decision.subscan.stop_scan_date = timezone.now()
            decision.subscan.save()
        decision.status = AssessmentDecision.STATUS_SKIPPED
        decision.policy_reason = (decision.policy_reason + '; ' if decision.policy_reason else '') + 'assessment stopped'
        decision.decided_at = timezone.now()
        decision.save()

    assessment.status = AutonomousAssessment.STATUS_STOPPED
    assessment.completed_at = timezone.now()
    assessment.completion_reason = reason
    assessment.save(update_fields=['status', 'completed_at', 'completion_reason', 'updated_at'])
    return assessment
