from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser
from django.db import models
from signalmeasure.models import SignalCableMeasure, SignalMeasure


class User(AbstractUser):
    full_name = models.CharField(max_length=255, null=True, blank=True)
    signal_measure = models.ForeignKey(
        SignalMeasure, on_delete=models.DO_NOTHING, null=True, blank=True
    )
    signal_measure_cable = models.ForeignKey(
        SignalCableMeasure, on_delete=models.DO_NOTHING, null=True, blank=True
    )
    email = models.EmailField(unique=True)
    # user_photo = models.ImageField()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self):
        return self.email
    
    def set_password_user(self, raw_password):
        self.password = make_password(raw_password)
        self._password = raw_password
    
    def check_password_user(self, raw_password):
        return check_password(raw_password, self.password)
