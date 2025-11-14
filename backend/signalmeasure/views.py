import time

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.shortcuts import get_list_or_404

from rest_framework import authentication, permissions, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework import viewsets

from .models import SignalCableMeasure, SignalMeasure
from .serializers import SignalMeasureSerializer, SignalCableMeasureSerializer
from .utils import SignalMeasureCableUtils, SignalMeasureUtils


class SignalAPICable(viewsets.GenericViewSet):
    # permission_classes = [permissions.IsAuthenticated]
    signal_cable_utils = SignalMeasureCableUtils
    signal_cable_serializer = SignalCableMeasureSerializer

    @method_decorator(csrf_exempt, name="dispatch") # TODO: REMOVE THIS LATER
    @action(detail=False, methods=["post"])
    # @csrf_protect
    def measure_signal(self, request):
        latency = request.data.get('L', request.query_params.get('L'))
        transfer_rate = request.data.get('TR', request.query_params.get('TR'))
        connection_type = request.data.get('CT', request.query_params.get('CR'))

        latency_bool = eval(latency)
        transfer_rate_bool = eval(transfer_rate)
        connection_type_bool = eval(connection_type)

        data = {}

        if latency_bool:
            data.update(self.signal_cable_utils.measure_latency())

        if transfer_rate_bool:
            data.update(self.signal_cable_utils.measure_transfer_rate())

        if connection_type_bool:
            data.update(self.signal_cable_utils.get_connection_type())

        if not data:
            return Response({"detail": "Erro no L ou TR"}, status=400)

        serializer = self.signal_cable_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=201)

    @action(detail=True, methods=["get"])
    def signal_history_cable(self, request, pk=None):
        """
        Get all signal cable measurements for the current user
        """
        queryset = SignalCableMeasure.objects.all()
        signal_cable = get_list_or_404(queryset, pk=pk)
        serializer = self.signal_cable_serializer(signal_cable)

        return Response(serializer.data)
        

class SignalMeasureAPI(viewsets.GenericViewSet):
    signal_utils = SignalMeasureUtils
    signal_serializer = SignalMeasureSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        
        latency = self.request.query_params.get('L')
        transfer_rate = self.request.query_params.get('TR')
        
        latency_bool = eval(latency)
        transfer_rate_bool = eval(transfer_rate)

    @action(detail=True, methods=["get"])
    def signal_history_cable(self, request):
        """
        Get recent signal cable measurements for the current user
        """
        ...
