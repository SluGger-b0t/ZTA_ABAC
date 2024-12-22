from django.urls import path
from .views import EMRAccessView

urlpatterns = [
    path("api/emr/<str:patient_id>/", EMRAccessView.as_view(), name="emr_access"),
]
