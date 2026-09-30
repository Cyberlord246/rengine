from django.contrib import admin

from autonomousMode.models import AssessmentDecision, AutonomousAssessment

admin.site.register(AutonomousAssessment)
admin.site.register(AssessmentDecision)
