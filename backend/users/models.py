from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from signalmeasure.models import SignalCableMeasure, SignalMeasure


class User(models.Model):
    name = models.CharField(max_length=255)
    signal_measure = models.ForeignKey(
        SignalMeasure, on_delete=models.CASCADE, null=True, blank=True
    )
    signal_measure_cable = models.ForeignKey(
        SignalCableMeasure, on_delete=models.DO_NOTHING, null=True, blank=True
    )
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    # user_photo = models.ImageField()
    
    def set_password_user(self, raw_password):
        self.password = make_password(raw_password)
        self._password = raw_password
    
    def check_password_user(self, raw_password):
        return check_password(raw_password, self.password)
