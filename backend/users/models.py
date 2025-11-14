from django.db import models
from signalmeasure.models import SignalMeasure, SignalMeasureCable


class User(models.Model):
    name = models.CharField(max_length=255)
    signal_measure = models.ForeignKey(
        SignalMeasure, on_delete=models.CASCADE, null=True, blank=True
    )
    signal_measure_cable = models.ForeignKey(
        SignalMeasureCable, on_delete=models.DO_NOTHING, null=True, black=True
    )
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField()
    # user_photo = models.ImageField()
