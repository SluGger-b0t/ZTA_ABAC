from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import EMR, User
from .utils import evaluate_policy_with_zta


class EMRAccessView(APIView):
    def get(self, request, patient_id):
        # Fetch user and EMR resource
        user = User.objects.get(username=request.user.username)
        emr = EMR.objects.get(patient_id=patient_id)

        # Gather device and location headers
        device_id = request.headers.get("Device-ID")
        location = request.headers.get("Location")

        # Evaluate policy
        decision = evaluate_policy_with_zta(user, "read", emr, device_id, location)
        if decision["decision"] == "PERMIT":
            return Response({"data": emr.data}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"error": decision["reason"]}, status=status.HTTP_403_FORBIDDEN
            )

    def post(self, request, patient_id):
        # Fetch user and EMR resource
        user = User.objects.get(username=request.user.username)
        emr = EMR.objects.get(patient_id=patient_id)

        # Gather device and location headers
        device_id = request.headers.get("Device-ID")
        location = request.headers.get("Location")

        # Evaluate policy
        decision = evaluate_policy_with_zta(user, "update", emr, device_id, location)
        if decision["decision"] == "PERMIT":
            emr.data = request.data.get("data")
            emr.save()
            return Response({"message": "Update successful"}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"error": decision["reason"]}, status=status.HTTP_403_FORBIDDEN
            )
