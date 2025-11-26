from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import SignalAPICable, SignalMeasureAPI

router = DefaultRouter()
router.register(r"signalcablemeasure", SignalAPICable, basename="signalcable")
router.register(r"signalmeasure", SignalMeasureAPI, basename="signalmeasure")

urlpatterns = [path("", include(router.urls))]
