from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import SignalAPICableView, SignalMeasureAPIView

router = DefaultRouter()
router.register(r"signalcablemeasure", SignalAPICableView, basename="signalcable")
router.register(r"signalmeasure", SignalMeasureAPIView, basename="signalmeasure")

urlpatterns = [path("", include(router.urls))]
