"""Consolidated report data builder for a multi-domain assessment.

Aggregates across the assessment's child scans, grouped by domain, and rolls
up the endpoint classifications by category. Pure data assembly (no rendering).
"""

from collections import defaultdict

from multiScan.correlation import correlation_summary
from multiScan.models import EndpointClassification


def build_report(assessment):
    """Return a dict the report template/API renders:
      { assessment, summary, by_category, domains }
    """
    summary = correlation_summary(assessment)

    # Classifications grouped by category, each with its endpoints + domain + source.
    by_category = defaultdict(list)
    qs = (
        EndpointClassification.objects
        .filter(assessment=assessment)
        .select_related('endpoint', 'domain')
        .order_by('category', '-confidence')
    )
    for c in qs:
        by_category[c.category].append({
            'url': c.endpoint.http_url if c.endpoint else None,
            'domain': c.domain.name if c.domain else None,
            'http_status': c.endpoint.http_status if c.endpoint else None,
            'signals': c.signals,
            'confidence': c.confidence,
            'source': (c.endpoint.source if c.endpoint else None),
        })

    return {
        'assessment_id': assessment.id,
        'assessment_name': assessment.name,
        'status': assessment.get_status_display(),
        'summary': summary,
        'by_category': {k: v for k, v in by_category.items()},
        'category_counts': {k: len(v) for k, v in by_category.items()},
    }
