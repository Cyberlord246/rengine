import uuid
from datetime import timedelta

from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.common_func import create_scan_object
from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    LIVE_SCAN,
    SUCCESS_TASK,
)
from reNgine.settings import RENGINE_RESULTS
from reNgine.tasks import initiate_scan, initiate_subscan
from reNgine.utilities import SubdomainScopeChecker
from startScan.models import ScanHistory, SubScan

from autonomousMode.decision_engine import next_candidates
from autonomousMode.models import AssessmentDecision, AutonomousAssessment
from autonomousMode.policy import PolicyEngine

logger = get_task_logger(__name__)

WATCHDOG_STALE_AFTER_SECONDS = 90
TERMINAL_SUBSCAN_STATUSES = {SUCCESS_TASK, FAILED_TASK, ABORTED_TASK}


def _next_sequence(assessment):
    last = assessment.decisions.order_by('-sequence').first()
    return (last.sequence + 1) if last else 1


def _claim_tick_lock(assessment):
    """Simple DB compare-and-set mutex so a watchdog re-enqueue racing an
    in-flight self-rescheduled tick can't double-dispatch for the same
    assessment. Returns the claimed token, or None if already locked."""
    token = uuid.uuid4().hex
    updated = AutonomousAssessment.objects.filter(
        id=assessment.id,
    ).exclude(
        tick_locked_at__gt=timezone.now() - timedelta(seconds=WATCHDOG_STALE_AFTER_SECONDS),
    ).update(tick_lock_token=token, tick_locked_at=timezone.now())
    return token if updated else None


def _release_tick_lock(assessment_id):
    AutonomousAssessment.objects.filter(id=assessment_id).update(tick_lock_token=None, tick_locked_at=None)


def bootstrap_scan(assessment):
    """First tick: kick off the normal initiate_scan() chain, exactly as a
    human-initiated scan would, and record it as the assessment's first
    decision."""
    scan_history_id = create_scan_object(
        host_id=assessment.domain.id,
        engine_id=assessment.engine.id,
        initiated_by_id=assessment.initiated_by.id,
    )
    scan = ScanHistory.objects.get(pk=scan_history_id)
    scan.cfg_out_of_scope_subdomains = assessment.cfg_out_of_scope_subdomains
    scan.cfg_imported_subdomains = assessment.cfg_imported_subdomains
    scan.cfg_starting_point_path = assessment.cfg_starting_point_path
    scan.cfg_excluded_paths = assessment.cfg_excluded_paths
    scan.save()

    kwargs = {
        'scan_history_id': scan.id,
        'domain_id': assessment.domain.id,
        'engine_id': assessment.engine.id,
        'scan_type': LIVE_SCAN,
        'results_dir': RENGINE_RESULTS,
        'imported_subdomains': assessment.cfg_imported_subdomains,
        'out_of_scope_subdomains': assessment.cfg_out_of_scope_subdomains,
        'starting_point_path': assessment.cfg_starting_point_path,
        'excluded_paths': assessment.cfg_excluded_paths,
        'initiated_by_id': assessment.initiated_by.id,
    }
    result = initiate_scan.apply_async(kwargs=kwargs)

    AssessmentDecision.objects.create(
        assessment=assessment,
        sequence=_next_sequence(assessment),
        action_type='initiate_scan',
        reason='Bootstrapping assessment: run the configured scan engine once to seed assets.',
        expected_outcome='Discover initial subdomains, ports, endpoints and findings to act on.',
        policy_check={'rbac': True, 'scope': True, 'engine_enabled': True, 'risk_level': True},
        policy_result=AssessmentDecision.POLICY_ALLOWED,
        policy_reason='Initial scan uses the operator-selected engine as-is.',
        status=AssessmentDecision.STATUS_DISPATCHED,
        celery_task_id=result.id,
        decided_at=timezone.now(),
    )

    assessment.scan_history = scan
    assessment.actions_taken_count += 1
    assessment.save(update_fields=['scan_history', 'actions_taken_count', 'updated_at'])


def reconcile_dispatched_decisions(assessment):
    """Link previously-dispatched decisions to the SubScan rows
    initiate_subscan() created for them (it creates SubScan internally, so
    the tick that dispatched it never gets the id synchronously), and copy
    over terminal results. Pure DB reads/writes - safe to call every tick."""
    dispatched = assessment.decisions.filter(
        status=AssessmentDecision.STATUS_DISPATCHED,
    ).exclude(action_type='initiate_scan')

    for decision in dispatched:
        subscan = decision.subscan
        if subscan is None:
            subscan = (
                SubScan.objects
                .filter(
                    scan_history=assessment.scan_history,
                    subdomain=decision.subdomain,
                    type=decision.action_type,
                    start_scan_date__gte=decision.created_at,
                )
                .order_by('-id')
                .first()
            )
            if subscan is None:
                continue
            decision.subscan = subscan
            decision.save(update_fields=['subscan'])

        if subscan.status in TERMINAL_SUBSCAN_STATUSES:
            decision.action_result_status = subscan.status
            decision.decided_at = timezone.now()
            decision.status = (
                AssessmentDecision.STATUS_COMPLETED
                if subscan.status == SUCCESS_TASK
                else AssessmentDecision.STATUS_FAILED
            )
            decision.save(update_fields=['action_result_status', 'decided_at', 'status'])

            if subscan.status == SUCCESS_TASK:
                assessment.consecutive_failures = 0
            else:
                assessment.consecutive_failures += 1
            assessment.save(update_fields=['consecutive_failures', 'updated_at'])

    # Also reconcile the bootstrap initiate_scan decision once the chain finishes.
    bootstrap = assessment.decisions.filter(
        action_type='initiate_scan', status=AssessmentDecision.STATUS_DISPATCHED,
    ).first()
    if bootstrap and assessment.scan_history and assessment.scan_history.scan_status in TERMINAL_SUBSCAN_STATUSES:
        bootstrap.action_result_status = assessment.scan_history.scan_status
        bootstrap.decided_at = timezone.now()
        bootstrap.status = (
            AssessmentDecision.STATUS_COMPLETED
            if assessment.scan_history.scan_status == SUCCESS_TASK
            else AssessmentDecision.STATUS_FAILED
        )
        bootstrap.save(update_fields=['action_result_status', 'decided_at', 'status'])


def dispatch_candidates(assessment):
    """Ask the decision engine for the next batch of candidates, run each
    through PolicyEngine, and dispatch/record accordingly. Also dispatches
    any previously-approved (human-approved) decisions still awaiting
    dispatch."""
    policy = PolicyEngine(assessment)

    approved_awaiting_dispatch = assessment.decisions.filter(
        status=AssessmentDecision.STATUS_APPROVED, subscan__isnull=True,
    )
    for decision in approved_awaiting_dispatch:
        if assessment.actions_taken_count >= assessment.max_actions:
            break
        _dispatch_one(assessment, decision.action_type, decision.subdomain, decision)

    if assessment.actions_taken_count >= assessment.max_actions:
        return

    candidates = next_candidates(assessment, limit=assessment.actions_per_tick)
    for candidate in candidates:
        if assessment.actions_taken_count >= assessment.max_actions:
            break

        result = policy.evaluate(candidate['action_type'], candidate['subdomain'])
        decision = AssessmentDecision.objects.create(
            assessment=assessment,
            sequence=_next_sequence(assessment),
            subdomain=candidate['subdomain'],
            action_type=candidate['action_type'],
            candidate_score=candidate['score'],
            reason=candidate['reason'],
            expected_outcome=candidate['expected_outcome'],
            policy_check=result.checks,
            policy_result=result.decision,
            policy_reason=result.reason,
            status=(
                AssessmentDecision.STATUS_PENDING
                if result.decision == 'requires_approval'
                else AssessmentDecision.STATUS_SKIPPED
            ),
        )

        if result.decision == 'allowed':
            _dispatch_one(assessment, candidate['action_type'], candidate['subdomain'], decision)
        elif result.decision == 'blocked':
            decision.decided_at = timezone.now()
            decision.save(update_fields=['decided_at'])
        # requires_approval: left as STATUS_PENDING for the approval-queue API


def _dispatch_one(assessment, action_type, subdomain, decision):
    ctx = {
        'scan_history_id': None,
        'subdomain_id': subdomain.id,
        'scan_type': action_type,
        'engine_id': assessment.engine.id,
    }
    result = initiate_subscan.apply_async(kwargs=ctx)
    decision.status = AssessmentDecision.STATUS_DISPATCHED
    decision.celery_task_id = result.id
    decision.decided_at = timezone.now()
    decision.save(update_fields=['status', 'celery_task_id', 'decided_at'])

    assessment.actions_taken_count += 1
    assessment.save(update_fields=['actions_taken_count', 'updated_at'])


def evaluate_stop_conditions(assessment):
    """Returns a (terminal_status, human-readable reason) tuple, or None to
    keep ticking."""
    if assessment.started_at:
        elapsed = timezone.now() - assessment.started_at
        if elapsed > timedelta(minutes=assessment.max_runtime_minutes):
            return (
                AutonomousAssessment.STATUS_COMPLETED,
                f'Time budget exhausted ({assessment.max_runtime_minutes} minute(s))',
            )

    if assessment.actions_taken_count >= assessment.max_actions:
        outstanding = assessment.decisions.filter(
            status__in=[AssessmentDecision.STATUS_DISPATCHED, AssessmentDecision.STATUS_PENDING],
        ).exists()
        if not outstanding:
            return (
                AutonomousAssessment.STATUS_COMPLETED,
                f'Action budget exhausted ({assessment.max_actions} action(s))',
            )

    if assessment.consecutive_failures >= assessment.failure_threshold:
        return (
            AutonomousAssessment.STATUS_FAILED,
            f'Stopped after {assessment.consecutive_failures} consecutive failed actions',
        )

    scope_checker = SubdomainScopeChecker(assessment.cfg_out_of_scope_subdomains or [])
    if scope_checker.is_out_of_scope(assessment.domain.name):
        return (AutonomousAssessment.STATUS_STOPPED, 'Target domain is out of scope')

    scan = assessment.scan_history
    if scan and scan.scan_status in TERMINAL_SUBSCAN_STATUSES:
        outstanding = assessment.decisions.filter(
            status__in=[AssessmentDecision.STATUS_DISPATCHED, AssessmentDecision.STATUS_PENDING],
        ).exists()
        if not outstanding and not next_candidates(assessment, limit=1):
            return (
                AutonomousAssessment.STATUS_COMPLETED,
                'No further authorized, meaningful actions available',
            )

    return None


def finalize_assessment(assessment, terminal_status, reason):
    assessment.status = terminal_status
    assessment.completed_at = timezone.now()
    assessment.completion_reason = reason
    assessment.save(update_fields=['status', 'completed_at', 'completion_reason', 'updated_at'])
    logger.info(f'Autonomous assessment {assessment.id} finished: {reason}')


@app.task(name='autonomous_loop_tick', bind=False, queue='autonomous_queue')
def autonomous_loop_tick(assessment_id):
    assessment = AutonomousAssessment.objects.filter(pk=assessment_id).first()
    if not assessment or assessment.status != AutonomousAssessment.STATUS_RUNNING:
        return

    token = _claim_tick_lock(assessment)
    if not token:
        return

    try:
        if assessment.scan_history is None:
            bootstrap_scan(assessment)
        else:
            reconcile_dispatched_decisions(assessment)

            stop_result = evaluate_stop_conditions(assessment)
            if stop_result:
                finalize_assessment(assessment, *stop_result)
                return

            dispatch_candidates(assessment)

        assessment.refresh_from_db()
        if assessment.status == AutonomousAssessment.STATUS_RUNNING:
            assessment.next_tick_eta = timezone.now() + timedelta(seconds=assessment.tick_interval_seconds)
            assessment.save(update_fields=['next_tick_eta', 'updated_at'])
    finally:
        _release_tick_lock(assessment_id)

    assessment.refresh_from_db()
    if assessment.status == AutonomousAssessment.STATUS_RUNNING:
        autonomous_loop_tick.apply_async(
            kwargs={'assessment_id': assessment_id},
            countdown=assessment.tick_interval_seconds,
        )


@app.task(name='autonomous_loop_watchdog', bind=False, queue='autonomous_queue')
def autonomous_loop_watchdog():
    """Safety net: re-enqueues any RUNNING assessment whose self-reschedule
    chain seems to have died (e.g. a worker crashed mid-tick)."""
    stale_before = timezone.now() - timedelta(seconds=WATCHDOG_STALE_AFTER_SECONDS)
    stale = AutonomousAssessment.objects.filter(
        status=AutonomousAssessment.STATUS_RUNNING,
        next_tick_eta__lt=stale_before,
    )
    for assessment in stale:
        logger.warning(f'Watchdog re-enqueuing stale autonomous assessment {assessment.id}')
        autonomous_loop_tick.delay(assessment.id)
