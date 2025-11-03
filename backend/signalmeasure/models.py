from django.db import models
from users.models import User


class SignalMeasure(models.Model):
    user = models.ForeignKey(User)
    amplitude = models.FloatField("Potência do sinal") # dBm
    frequency = models.FloatField(help_text="Frequência em MHz ou GHZ", null=True, blank=True) # 2.4 GHZ or 5GHz
    period = models.FloatField(help_text="Período de medição ou latência em segundos",
                               null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ssid = models.CharField(max_length=100, blank=True, null=True) # Network name
    bssid = models.CharField(max_length=17, blank=True, null=True) # AP MAC address
    
    
    class Meta:
        ordering = ['-timestamp']
