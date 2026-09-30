from django.urls import path

from . import views

urlpatterns = [
    path(
        '<slug:slug>/assessment/<int:assessment_id>/report/',
        views.assessment_report,
        name='assessment_report'),
]
