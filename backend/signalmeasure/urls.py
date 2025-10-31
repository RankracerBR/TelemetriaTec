from rest_framework.routers import DefaultRouter
from .views import SignalMeasureViewSet


router = DefaultRouter()
router.register(r'signal-measures', SignalMeasureViewSet, basename='signalmeasure')

urlpatterns = router.urls