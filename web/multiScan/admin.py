from django.contrib import admin

from multiScan.models import Assessment, AssessmentDomainRun, EndpointClassification

admin.site.register(Assessment)
admin.site.register(AssessmentDomainRun)
admin.site.register(EndpointClassification)
