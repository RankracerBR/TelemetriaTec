from django.db import models
from users.models import User


class SignalMeasure(models.Model):
    user = models.ForeignKey(User)
    amplitude = models.FloatField("Potência do sinal")
    frequency = models.FloatField(help_text="Frequência em MHz ou GHZ", null=True, blank=True)
    period = models.FloatField(help_text="Período de medição ou latência em segundos",
                               null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']