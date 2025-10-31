from rest_framework import viewsets, permissions
from .models import SignalMeasure
from .serializers import SignalMeasureSerializer


class SignalMeasureViewSet(viewsets.ModelViewSet):
    queryset = SignalMeasure.objects.all()
    serializer_class = SignalMeasureSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return SignalMeasure.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


