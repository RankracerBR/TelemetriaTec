from rest_framework import serializers

from .models import SignalMeasure, SignalCableMeasure


class SignalMeasureSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignalMeasure
        fields = '__all__'
        read_only_fields = ["id", "timestamp"]


class SignalCableMeasureSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignalCableMeasure
        fields = '__all__'
        read_only_fields = ["id", "timestamp"]
