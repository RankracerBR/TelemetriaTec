from rest_framework import serializers

from .models import SignalMeasure


class SignalMeasureSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignalMeasure
        fields = ["id", "user", "amplitude", "frequency", "period", "timestamp"]
        read_only_fields = ["id", "timestamp"]
