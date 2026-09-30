from django.shortcuts import get_object_or_404, render
from rolepermissions.decorators import has_permission_decorator

from reNgine.definitions import FOUR_OH_FOUR_URL, PERM_INITATE_SCANS_SUBSCANS

from multiScan.models import Assessment


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def assessment_report(request, slug, assessment_id):
    assessment = get_object_or_404(Assessment, id=assessment_id)
    context = {
        'scan_history_active': 'active',
        'assessment_id': assessment.id,
        'assessment': assessment,
        'slug': slug,
    }
    return render(request, 'multiScan/assessment_report.html', context)
