from django.urls import path
from .views import SignalAPIMethods


urlpatterns = [
    path('measure/', SignalAPIMethods.measure_signal, name='measure-signal'),
    path('history/', SignalAPIMethods.signal_history, name='signal-history'),
]
