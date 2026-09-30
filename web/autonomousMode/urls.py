from django.urls import path

from . import views

urlpatterns = [
    path(
        '<slug:slug>/assessment/<int:assessment_id>/',
        views.assessment_status,
        name='assessment_status'),
]
