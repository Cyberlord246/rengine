from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models

from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory, Subdomain, SubScan
from targetApp.models import Domain


class AutonomousAssessment(models.Model):
    """A continuously self-directed assessment (AI-Assisted or Autonomous mode).

    Owns none of reNgine's execution machinery: it only decides which of the
    *existing* scan/subscan tasks to dispatch next, and every dispatch still
    goes through the existing initiate_scan/initiate_subscan Celery entrypoints.
    """

    MODE_AI_ASSISTED = 1
    MODE_AUTONOMOUS = 2
    MODE_CHOICES = (
        (MODE_AI_ASSISTED, 'AI-Assisted'),
        (MODE_AUTONOMOUS, 'Autonomous'),
    )

    RISK_SAFE = 0
    RISK_STANDARD = 1
    RISK_CONTROLLED = 2
    RISK_CHOICES = (
        (RISK_SAFE, 'Safe'),
        (RISK_STANDARD, 'Standard'),
        (RISK_CONTROLLED, 'Controlled'),
    )

    STATUS_FAILED = 0
    STATUS_RUNNING = 1
    STATUS_COMPLETED = 2
    STATUS_STOPPED = 3
    STATUS_PAUSED = 4
    STATUS_PENDING = -1
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_STOPPED, 'Stopped'),
        (STATUS_PAUSED, 'Paused'),
    )

    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='autonomous_assessments')
    engine = models.ForeignKey(EngineType, on_delete=models.CASCADE)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.SET_NULL, null=True, blank=True)

    mode = models.IntegerField(choices=MODE_CHOICES)
    risk_level = models.IntegerField(choices=RISK_CHOICES, default=RISK_SAFE)
    status = models.IntegerField(choices=STATUS_CHOICES, default=STATUS_PENDING)

    # Budgets / stop conditions
    max_runtime_minutes = models.IntegerField(default=240)
    max_actions = models.IntegerField(default=50)
    actions_per_tick = models.IntegerField(default=2)
    tick_interval_seconds = models.IntegerField(default=30)
    failure_threshold = models.IntegerField(default=5)

    # Running counters
    actions_taken_count = models.IntegerField(default=0)
    consecutive_failures = models.IntegerField(default=0)

    # Scope config, mirrors ScanHistory.cfg_* fields (needed before a
    # ScanHistory exists, and reused verbatim once it does).
    cfg_out_of_scope_subdomains = ArrayField(
        models.CharField(max_length=200), blank=True, null=True, default=list)
    cfg_imported_subdomains = ArrayField(
        models.CharField(max_length=200), blank=True, null=True, default=list)
    cfg_starting_point_path = models.CharField(max_length=200, blank=True, null=True)
    cfg_excluded_paths = ArrayField(
        models.CharField(max_length=200), blank=True, null=True, default=list)

    initiated_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='autonomous_assessments')
    started_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    completion_reason = models.CharField(max_length=300, blank=True, null=True)

    # Loop scheduling / crash recovery bookkeeping
    next_tick_eta = models.DateTimeField(null=True, blank=True)
    tick_lock_token = models.CharField(max_length=64, null=True, blank=True)
    tick_locked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'{self.domain.name} ({self.get_mode_display()}, {self.get_status_display()})'


class AssessmentDecision(models.Model):
    """One row per loop decision: Decision / Reason / Expected outcome / Policy / Action / Result."""

    POLICY_ALLOWED = 'allowed'
    POLICY_BLOCKED = 'blocked'
    POLICY_REQUIRES_APPROVAL = 'requires_approval'
    POLICY_CHOICES = (
        (POLICY_ALLOWED, 'Allowed'),
        (POLICY_BLOCKED, 'Blocked'),
        (POLICY_REQUIRES_APPROVAL, 'Requires approval'),
    )

    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_DISPATCHED = 'dispatched'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'
    STATUS_SKIPPED = 'skipped'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_DISPATCHED, 'Dispatched'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_SKIPPED, 'Skipped'),
    )

    id = models.AutoField(primary_key=True)
    assessment = models.ForeignKey(
        AutonomousAssessment, on_delete=models.CASCADE, related_name='decisions')
    sequence = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    subdomain = models.ForeignKey(Subdomain, null=True, blank=True, on_delete=models.SET_NULL)
    endpoint = models.ForeignKey(EndPoint, null=True, blank=True, on_delete=models.SET_NULL)
    action_type = models.CharField(max_length=100)

    candidate_score = models.FloatField(default=0)
    reason = models.TextField(blank=True)
    expected_outcome = models.TextField(blank=True)

    policy_check = models.JSONField(default=dict)
    policy_result = models.CharField(max_length=20, choices=POLICY_CHOICES, default=POLICY_ALLOWED)
    policy_reason = models.TextField(blank=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    subscan = models.ForeignKey(SubScan, null=True, blank=True, on_delete=models.SET_NULL)
    celery_task_id = models.CharField(max_length=100, blank=True, null=True)
    action_result_status = models.IntegerField(null=True, blank=True)

    approved_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='approved_decisions')
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['sequence']
        unique_together = ('assessment', 'sequence')

    def __str__(self):
        target = self.subdomain.name if self.subdomain else self.assessment.domain.name
        return f'#{self.sequence} {self.action_type} on {target} ({self.policy_result}/{self.status})'
