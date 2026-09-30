from django.contrib import admin

from reconIntel.models import (
    DiscoveredSecret,
    FindingScore,
    HttpParameter,
    OriginIpCandidate,
)

admin.site.register(DiscoveredSecret)
admin.site.register(HttpParameter)
admin.site.register(OriginIpCandidate)
admin.site.register(FindingScore)
