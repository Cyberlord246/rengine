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
from startScan.models import ScanHistory

from multiScan import correlation, orchestrator
from multiScan.models import Assessment, AssessmentDomainRun

logger = get_task_logger(__name__)

WATCHDOG_STALE_AFTER_SECONDS = 120


def _claim_lock(assessment):
    token = uuid.uuid4().hex
    updated = Assessment.objects.filter(id=assessment.id).exclude(
        tick_locked_at__gt=timezone.now() - timedelta(seconds=WATCHDOG_STALE_AFTER_SECONDS),
    ).update(tick_lock_token=token, tick_locked_at=timezone.now())
    return token if updated else None


def _release_lock(assessment_id):
    Assessment.objects.filter(id=assessment_id).update(tick_lock_token=None, tick_locked_at=None)


def reconcile(assessment):
    """Copy child-scan status onto each running domain run. Per-domain failure
    is isolated - it never stops the assessment."""
    for run in assessment.domain_runs.filter(status=AssessmentDomainRun.STATUS_RUNNING):
        scan = run.scan_history
        if not scan:
            continue
        scan.refresh_from_db()
        if orchestrator.is_scan_terminal(scan.scan_status):
            run.finished_at = timezone.now()
            if scan.scan_status == SUCCESS_TASK:
                run.status = AssessmentDomainRun.STATUS_COMPLETED
            else:
                run.status = AssessmentDomainRun.STATUS_FAILED
                run.error = 'scan aborted' if scan.scan_status == ABORTED_TASK else 'scan failed'
            run.save(update_fields=['status', 'finished_at', 'error'])


def launch_domain(assessment, run, batch_index):
    """Launch one domain through the EXISTING per-domain pipeline."""
    from reNgine.tasks import initiate_scan  # lazy import breaks the tasks<->tasks cycle
    try:
        scan_history_id = create_scan_object(
            host_id=run.domain.id,
            engine_id=assessment.engine.id,
            initiated_by_id=assessment.initiated_by.id,
        )
        scan = ScanHistory.objects.get(pk=scan_history_id)
        scan.cfg_out_of_scope_subdomains = assessment.cfg_out_of_scope_subdomains or []
        scan.save()
        kwargs = {
            'scan_history_id': scan.id,
            'domain_id': run.domain.id,
            'engine_id': assessment.engine.id,
            'scan_type': LIVE_SCAN,
            'results_dir': RENGINE_RESULTS,
            'imported_subdomains': [],
            'out_of_scope_subdomains': assessment.cfg_out_of_scope_subdomains or [],
            'starting_point_path': '',
            'excluded_paths': [],
            'initiated_by_id': assessment.initiated_by.id,
        }
        initiate_scan.apply_async(kwargs=kwargs)
        run.scan_history = scan
        run.status = AssessmentDomainRun.STATUS_RUNNING
        run.batch_index = batch_index
        run.started_at = timezone.now()
        run.save(update_fields=['scan_history', 'status', 'batch_index', 'started_at'])
    except Exception as e:
        # Isolate the failure to this domain.
        run.status = AssessmentDomainRun.STATUS_FAILED
        run.error = str(e)[:500]
        run.finished_at = timezone.now()
        run.save(update_fields=['status', 'error', 'finished_at'])
        logger.error(f'Failed to launch domain {run.domain.name}: {e}')


def finalize(assessment, reason, status):
    correlation.classify_assessment_endpoints(assessment)
    assessment.status = status
    assessment.completed_at = timezone.now()
    assessment.completion_reason = reason
    assessment.save(update_fields=['status', 'completed_at', 'completion_reason', 'updated_at'])
    logger.info(f'Assessment {assessment.id} finished: {reason}')


@app.task(name='assessment_tick', bind=False, queue='multiscan_queue')
def assessment_tick(assessment_id):
    assessment = Assessment.objects.filter(pk=assessment_id).first()
    if not assessment or assessment.status != Assessment.STATUS_RUNNING:
        return

    token = _claim_lock(assessment)
    if not token:
        return

    try:
        reconcile(assessment)
        runs = list(assessment.domain_runs.all())

        # Runtime budget stop.
        if assessment.started_at:
            elapsed = timezone.now() - assessment.started_at
            if elapsed > timedelta(minutes=assessment.max_runtime_minutes):
                finalize(assessment, 'Runtime budget exhausted', Assessment.STATUS_STOPPED)
                return

        # All done -> finalize + consolidated results.
        if orchestrator.all_runs_terminal(runs):
            finalize(assessment, 'All domains processed', Assessment.STATUS_COMPLETED)
            return

        # Advance batch: launch up to (batch_size - running) pending domains.
        to_launch = orchestrator.select_next_domains(runs, assessment.batch_size)
        current_batch = (max([r.batch_index or 0 for r in runs]) + 1) if to_launch else None
        for run in to_launch:
            launch_domain(assessment, run, current_batch)

        assessment.next_tick_eta = timezone.now() + timedelta(seconds=assessment.tick_interval_seconds)
        assessment.save(update_fields=['next_tick_eta', 'updated_at'])
    finally:
        _release_lock(assessment_id)

    assessment.refresh_from_db()
    if assessment.status == Assessment.STATUS_RUNNING:
        assessment_tick.apply_async(kwargs={'assessment_id': assessment_id},
                                    countdown=assessment.tick_interval_seconds)


@app.task(name='assessment_watchdog', bind=False, queue='multiscan_queue')
def assessment_watchdog():
    stale = timezone.now() - timedelta(seconds=WATCHDOG_STALE_AFTER_SECONDS)
    for a in Assessment.objects.filter(status=Assessment.STATUS_RUNNING, next_tick_eta__lt=stale):
        logger.warning(f'Watchdog re-enqueuing stale assessment {a.id}')
        assessment_tick.delay(a.id)
