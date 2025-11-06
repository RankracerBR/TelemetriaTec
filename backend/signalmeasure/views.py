from rest_framework import status, permissions, authentication
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.utils.decorators import method_decorator

from .models import SignalMeasure
from .serializers import SignalMeasureSerializer
from .utils import SignalStrength
import time


class SignalAPIMethods(ViewSet):
    # permission_classes = [permissions.IsAuthenticated]

    @method_decorator(csrf_exempt, name='dispatch')
    @action(detail=False, methods=['post'])
    # @csrf_protect
    def measure_signal(self, request):
        duration = float(request.data.get('duration', 5))
        interface = request.data.get('interface', 'wlan0')
        
        start_time = time.time()
        amplitude = SignalStrength.wifi_strength(interface, duration)
        end_time = time.time()
        
        period = end_time - start_time
        
        measurement_data: dict = {
            'amplitude': amplitude,
            'period': period, 
            'user': request.user.id
        }
        
        serializer = SignalMeasureSerializer(data=measurement_data)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': 'success',
                'amplitude': f'{amplitude:.2f} dBm',
                'period': f'{period:.2f} seconds',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def signal_history(self, request):
        """
        Get recent signal measurements for the current user
        """
        measurements = SignalMeasure.objects.filter(user=request.user)[:10]
        serializer = SignalMeasureSerializer(measurements, many=True)
        return Response(serializer.data)
