from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import UserAPIView


router = DefaultRouter()
router.register(r"userapiview", UserAPIView, basename="userapiview")

urlpatterns = [path("", include(router.urls))]
