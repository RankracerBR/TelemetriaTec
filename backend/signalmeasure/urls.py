from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import SignalAPIMethods

router = DefaultRouter()
router.register(r"signal", SignalAPIMethods, basename="signal")

urlpatterns = [path("", include(router.urls))]
