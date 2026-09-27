from django.db import models

from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class DiscoveredSecret(models.Model):
    """A secret-looking string found while analyzing JavaScript / responses.

    Only a masked snippet is ever stored - never the full secret value.
    """
    SEVERITY_INFO = 0
    SEVERITY_LOW = 1
    SEVERITY_MEDIUM = 2
    SEVERITY_HIGH = 3
    SEVERITY_CRITICAL = 4
    SEVERITY_CHOICES = (
        (SEVERITY_INFO, 'Info'),
        (SEVERITY_LOW, 'Low'),
        (SEVERITY_MEDIUM, 'Medium'),
        (SEVERITY_HIGH, 'High'),
        (SEVERITY_CRITICAL, 'Critical'),
    )

    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.SET_NULL, null=True, blank=True)
    secret_type = models.CharField(max_length=100)
    severity = models.IntegerField(choices=SEVERITY_CHOICES, default=SEVERITY_MEDIUM)
    redacted_snippet = models.CharField(max_length=500)
    source_url = models.CharField(max_length=10000, blank=True, null=True)
    discovered_date = models.DateTimeField(null=True, blank=True)
    is_false_positive = models.BooleanField(default=False)

    class Meta:
        unique_together = ('scan_history', 'secret_type', 'redacted_snippet', 'source_url')

    def __str__(self):
        return f'{self.secret_type} in {self.source_url}'


class HttpParameter(models.Model):
    """A request parameter name discovered for an endpoint/host."""
    TYPE_QUERY = 'query'
    TYPE_BODY = 'body'
    TYPE_JSON = 'json'
    TYPE_CHOICES = (
        (TYPE_QUERY, 'Query'),
        (TYPE_BODY, 'Body'),
        (TYPE_JSON, 'JSON'),
    )

    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=500)
    param_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default=TYPE_QUERY)
    source = models.CharField(max_length=50, blank=True, null=True)
    discovered_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('endpoint', 'name', 'param_type')

    def __str__(self):
        return f'{self.name} ({self.param_type})'


class OriginIpCandidate(models.Model):
    """A candidate real/origin IP for a domain, possibly behind a CDN/WAF."""
    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=45)
    source = models.CharField(max_length=50)
    confidence = models.IntegerField(default=0)
    is_behind_cdn_bypass = models.BooleanField(default=False)
    discovered_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('scan_history', 'domain', 'ip_address', 'source')

    def __str__(self):
        return f'{self.ip_address} ({self.source}, {self.confidence}%)'


class FindingScore(models.Model):
    """Deterministic rule-based triage score for a Vulnerability.

    Kept as a separate OneToOne model so the core startScan.Vulnerability
    model does not need to change.
    """
    id = models.AutoField(primary_key=True)
    vulnerability = models.OneToOneField(
        Vulnerability, on_delete=models.CASCADE, related_name='finding_score')
    risk_score = models.FloatField(default=0)
    confidence = models.FloatField(default=0)
    is_likely_false_positive = models.BooleanField(default=False)
    rationale = models.TextField(blank=True)
    scored_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'score={self.risk_score:.1f} for vuln {self.vulnerability_id}'
