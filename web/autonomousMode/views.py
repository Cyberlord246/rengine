from django.shortcuts import get_object_or_404, render
from rolepermissions.decorators import has_permission_decorator

from reNgine.definitions import FOUR_OH_FOUR_URL, PERM_INITATE_SCANS_SUBSCANS

from autonomousMode.models import AutonomousAssessment


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def assessment_status(request, slug, assessment_id):
    assessment = get_object_or_404(
        AutonomousAssessment, id=assessment_id, domain__project__slug=slug)
    context = {
        'scan_history_active': 'active',
        'assessment_id': assessment.id,
        'assessment': assessment,
        'slug': slug,
    }
    return render(request, 'autonomousMode/assessment_status.html', context)
