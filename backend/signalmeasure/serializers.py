from rest_framework import serializers

from .models import SignalMeasure, SignalCableMeasure


class SignalMeasureSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignalMeasure
        fields = ["id", "amplitude", "frequency", "period", "timestamp"]
        read_only_fields = ["id", "timestamp"]


class SignalCableMeasureSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignalCableMeasure
        field = ["id", "latency", "transfer_rate", "connection_type", "timestamp"]
        read_only_fields = ["id", "timestamp"]
