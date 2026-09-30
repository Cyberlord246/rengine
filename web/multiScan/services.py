"""Entry points to control an Assessment, callable from API and page views."""

from django.utils import timezone

from reNgine.celery import app
from reNgine.definitions import ABORTED_TASK

from multiScan.models import Assessment, AssessmentDomainRun


def start_assessment(name, project, engine, domains, user, **opts):
    """Create a multi-domain assessment and begin coordinated batched execution."""
    assessment = Assessment(
        name=name,
        project=project,
        engine=engine,
        initiated_by=user,
        status=Assessment.STATUS_RUNNING,
        started_at=timezone.now(),
        next_tick_eta=timezone.now(),
    )
    for field in ('batch_size', 'tick_interval_seconds', 'max_runtime_minutes'):
        if opts.get(field):
            setattr(assessment, field, opts[field])
    assessment.cfg_out_of_scope_subdomains = opts.get('out_of_scope_subdomains') or []
    assessment.save()
    assessment.domains.set(domains)

    # One resumable run row per domain.
    for domain in domains:
        AssessmentDomainRun.objects.get_or_create(assessment=assessment, domain=domain)

    from multiScan.tasks import assessment_tick
    assessment_tick.delay(assessment.id)
    return assessment


def pause_assessment(assessment):
    assessment.status = Assessment.STATUS_PAUSED
    assessment.save(update_fields=['status', 'updated_at'])
    return assessment


def resume_assessment(assessment):
    assessment.status = Assessment.STATUS_RUNNING
    assessment.next_tick_eta = timezone.now()
    assessment.save(update_fields=['status', 'next_tick_eta', 'updated_at'])
    from multiScan.tasks import assessment_tick
    assessment_tick.delay(assessment.id)
    return assessment


def stop_assessment(assessment, reason='Stopped by user'):
    # Abort any in-flight child scans (same revoke approach as StopScan).
    for run in assessment.domain_runs.filter(status=AssessmentDomainRun.STATUS_RUNNING):
        scan = run.scan_history
        if scan:
            for task_id in (scan.celery_ids or []):
                app.control.revoke(task_id, terminate=True, signal='SIGKILL')
            scan.scan_status = ABORTED_TASK
            scan.stop_scan_date = timezone.now()
            scan.save(update_fields=['scan_status', 'stop_scan_date'])
        run.status = AssessmentDomainRun.STATUS_FAILED
        run.error = 'assessment stopped'
        run.finished_at = timezone.now()
        run.save(update_fields=['status', 'error', 'finished_at'])

    assessment.status = Assessment.STATUS_STOPPED
    assessment.completed_at = timezone.now()
    assessment.completion_reason = reason
    assessment.save(update_fields=['status', 'completed_at', 'completion_reason', 'updated_at'])
    return assessment
