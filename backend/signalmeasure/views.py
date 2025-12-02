import time

from django.shortcuts import get_list_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from rest_framework import authentication, permissions, status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.response import Response

from .models import SignalCableMeasure, SignalMeasure
from .serializers import SignalCableMeasureSerializer, SignalMeasureSerializer
from .utils import SignalMeasureCableUtils, SignalMeasureUtils


class SignalAPICableView(viewsets.GenericViewSet):
    # permission_classes = [permissions.IsAuthenticated]
    
    signal_cable_utils = SignalMeasureCableUtils
    signal_cable_serializer = SignalCableMeasureSerializer

    @method_decorator(csrf_exempt, name="dispatch") # TODO: REMOVE THIS LATER
    @action(detail=False, methods=["post"])
    # @csrf_protect
    def measure_signal(self, request):
        """
        Measures for cable connection
        """

        latency_param = request.data.get('L') or request.query_params.get('L')
        transfer_rate_download_param = request.data.get('TRD') or request.query_params.get('TRD')
        transfer_rate_upload_param = request.data.get('TRU') or request.query_params.get('TRU')
        connection_type_param = request.data.get('CT') or request.query_params.get('CT')

        latency_bool = safe_bool_convert(latency_param)
        transfer_rate_download_bool = safe_bool_convert(transfer_rate_download_param)
        transfer_rate_upload_bool = safe_bool_convert(transfer_rate_upload_param)
        connection_type_bool = safe_bool_convert(connection_type_param)

        data = {}
        utils = self.signal_cable_utils()

        if latency_bool:
            latency_value, _ = utils.measure_latency()
            if latency_value is not None:
                data['latency'] = latency_value

        if transfer_rate_download_bool or transfer_rate_upload_bool:
            download_speed, upload_speed = utils.measure_transfer_rate()
        
            if transfer_rate_download_bool and download_speed is not None:
                data['transfer_rate_download'] = download_speed
            if transfer_rate_upload_bool and upload_speed is not None:
                data['transfer_rate_upload'] = upload_speed

        if connection_type_bool:
            connection_type_value = utils.get_connection_type()
            if connection_type_value:
                data['connection_type'] = connection_type_value

        if not data:
            return Response({"detail": "Nenhuma medição foi solicitada ou todas falharam"}, status=400)

        serializer = self.signal_cable_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        else:
            return Response(serializer.errors, status=400)

    @method_decorator(csrf_exempt, name="dispatch")
    @action(detail=False, methods=["get"])
    def signal_history_cable(self, request):
        """
        Get all signal cable measurements for the current user
        """
        queryset = SignalCableMeasure.objects.all().order_by("-timestamp")

        signal_cables = get_list_or_404(queryset)
        serializer = self.signal_cable_serializer(signal_cables, many=True)
        return Response(serializer.data)


class SignalMeasureAPIView(viewsets.GenericViewSet):
    # permission_classes = [permissions.IsAuthenticated]

    signal_utils = SignalMeasureUtils
    signal_serializer = SignalMeasureSerializer

    def measure_signal(self, request):
        latency = request.data.get('L', request.query_params.get('L'))
        transfer_rate = request.data.get('TR', request.query_params.get('TR'))
        connection_type = request.data.get('CT', request.query_params.get('CR'))

        latency_bool = eval(latency)
        transfer_rate_bool = eval(transfer_rate)
        connection_type_bool = eval(connection_type)

        data = {}

        if latency_bool:
            data.update(self.signal_utils.measure_latency())
        if transfer_rate_bool:
            data.update(self.signal_utils.measure_transfer_rate())
        if connection_type_bool:
            data.update(self.signal_utils.get_connection_type())

        if not data:
            return Response({"detail": "Erro no L, TR ou CT"}, status=400)

        serializer = self.signal_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=201)

    @action(detail=True, methods=["get"])
    def signal_history_cable(self, request, pk=None):
        """
        Get recent signal measurements for the current user
        """
        queryset = SignalMeasure.objects.all()
        signal_cable = get_list_or_404(queryset, pk=pk)
        serializer = self.signal_serializer(signal_cable)

        return Response(serializer.data)


def safe_bool_convert(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ['true', '1', 'yes', 'y', 't']
    return bool(value)