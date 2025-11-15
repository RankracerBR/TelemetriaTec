from django.db import models


class SignalCableMeasure(models.Model):
    latency = models.FloatField(verbose_name="Medição latência(Cabeada)")
    transfer_rate = models.FloatField(
        verbose_name="Taxa de transferência(Cabeada)",
        blank=True, null=True
    )
    connection_type = models.CharField(verbose_name="Tipo Conexão", blank=True, null=True)
    timestamp = models.DateField(verbose_name="Horario do teste", auto_now=True)


class SignalMeasure(models.Model):
    amplitude = models.FloatField(
        verbose_name="Potência do sinal", null=True, blank=True
    )  # dBm
    frequency = models.FloatField(
        verbose_name="Frequência",
        help_text="Frequência em MHz ou GHZ", null=True, blank=True
    )  # 2.4 GHZ or 5GHz
    period = models.FloatField(
        verbose_name="Período",
        help_text="Período de medição ou latência em segundos", 
        null=True, blank=True
    )
    latency = models.FloatField(
        verbose_name="Latência", help_text="Medição da latência(Não cabeada)"
    )
    transfer_rate = models.FloatField(
        verbose_name="Taxa de transferência", 
        help_text="Taxa de transferência(Não cabeada)"
    )
    ssid = models.CharField(
        verbose_name="SSID", max_length=100, blank=True, null=True
    )  # Network name
    bssid = models.CharField(
        verbose_name="BSSID", max_length=17, blank=True, null=True
    )  # AP MAC address
    connection_type = models.CharField(
        "Tipo de conexão(Não cabeada)", null=True, blank=True
    )
    timestamp = models.DateTimeField(
        verbose_name="Horário do teste(Não cabeado)", auto_now=True
    )

    class Meta:
        ordering = ["-timestamp"]
