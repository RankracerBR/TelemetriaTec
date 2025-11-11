import time

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from rest_framework import authentication, permissions, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from .models import SignalMeasure
from .serializers import SignalMeasureSerializer
from .utils import SignalStrength


class SignalAPIMethods(ViewSet):
    # permission_classes = [permissions.IsAuthenticated]

    @method_decorator(csrf_exempt, name="dispatch")
    @action(detail=False, methods=["post"])
    # @csrf_protect
    def measure_signal(self, request):
        duration = float(request.data.get("duration", 5))
        interface = request.data.get("interface", "eth0")

        start_time = time.time()
        result = SignalStrength.wifi_strength(interface, duration)
        if isinstance(result, tuple):
            amplitude, frequency = result
        else:
            return Response({"error": str(result)}, status=status.HTTP_400_BAD_REQUEST)
        end_time = time.time()
        period = end_time - start_time

        measurement_data: dict = {
            "amplitude": amplitude,
            "frequency": frequency,
            "period": period,
            "user": request.user.id,
        }

        serializer = SignalMeasureSerializer(data=measurement_data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "success",
                    "amplitude": f"{amplitude} dBm" if amplitude is not None else None,
                    "frequency": f"{frequency} MHz" if frequency is not None else None,
                    "period": f"{period:.2f} seconds",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["get"])
    def signal_history(self, request):
        """
        Get recent signal measurements for the current user
        """
        measurements = SignalMeasure.objects.filter(user=request.user)[:10]
        serializer = SignalMeasureSerializer(measurements, many=True)
        return Response(serializer.data)
