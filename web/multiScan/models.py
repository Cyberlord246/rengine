from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models

from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory
from targetApp.models import Domain

from multiScan.classification import CATEGORY_CHOICES


class Assessment(models.Model):
    """One logical multi-domain assessment. Wraps N in-scope domains and
    coordinates their (existing, per-domain) scans as one batched, resumable,
    consolidated job."""

    STATUS_PENDING = -1
    STATUS_FAILED = 0
    STATUS_RUNNING = 1
    STATUS_COMPLETED = 2
    STATUS_STOPPED = 3
    STATUS_PAUSED = 4
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_STOPPED, 'Stopped'),
        (STATUS_PAUSED, 'Paused'),
    )

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300)
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, null=True, blank=True)
    engine = models.ForeignKey(EngineType, on_delete=models.CASCADE)
    domains = models.ManyToManyField(Domain, related_name='assessments')
    status = models.IntegerField(choices=STATUS_CHOICES, default=STATUS_PENDING)

    # Resource controls (the crash fix): never more than batch_size domains run
    # at once, regardless of how many are in the assessment.
    batch_size = models.IntegerField(default=5)
    tick_interval_seconds = models.IntegerField(default=30)
    max_runtime_minutes = models.IntegerField(default=1440)

    # Scope carried onto every child scan.
    cfg_out_of_scope_subdomains = ArrayField(
        models.CharField(max_length=200), blank=True, null=True, default=list)

    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='assessments')
    started_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    completion_reason = models.CharField(max_length=300, blank=True, null=True)

    # Loop scheduling / crash-recovery bookkeeping (same pattern as autonomousMode).
    next_tick_eta = models.DateTimeField(null=True, blank=True)
    tick_lock_token = models.CharField(max_length=64, null=True, blank=True)
    tick_locked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'{self.name} ({self.get_status_display()})'


class AssessmentDomainRun(models.Model):
    """Per-domain run state within an assessment: the resumable unit and the
    domain-level grouping of results."""

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_FAILED, 'Failed'),
    )

    id = models.AutoField(primary_key=True)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='domain_runs')
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    batch_index = models.IntegerField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        unique_together = ('assessment', 'domain')
        ordering = ['id']

    def __str__(self):
        return f'{self.domain.name} [{self.status}]'


class EndpointClassification(models.Model):
    """An endpoint categorized as a manual-validation candidate. Never
    auto-exploited."""

    id = models.AutoField(primary_key=True)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='classifications')
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, null=True, blank=True)
    category = models.CharField(max_length=40, choices=CATEGORY_CHOICES)
    signals = models.JSONField(default=list)
    confidence = models.FloatField(default=0)

    class Meta:
        unique_together = ('assessment', 'endpoint', 'category')

    def __str__(self):
        return f'{self.category} <- {self.endpoint_id}'
