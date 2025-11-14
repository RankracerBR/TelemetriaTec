from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, RadioTap
from scapy.sendrecv import sniff
from scapy.plist import PacketList

import subprocess
import netifaces
import speedtest

from .models import SignalCableMeasure, SignalMeasure


class SignalMeasureCableUtils:
    model = SignalCableMeasure

    def measure_latency():
        ...

    def measure_transfer_rate():
        ...

    def get_connection_type():
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {})
        
        if netifaces.AF_INET in default_gateway:
            active_interface = default_gateway[netifaces.AF_INET][1]
            return active_interface
        return "Interface not detected"

class SignalMeasureUtils:
    model = SignalMeasure

    def measure_amplitude():
        ...
    
    def measure_frequency():
        ...
    
    def measure_period():
        ...
    
    def measure_latency():
        ...
    
    def measure_transfer_rate():
        ...

    def get_connection_type():
        ...
