from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, RadioTap
from scapy.sendrecv import sniff
from scapy.plist import PacketList

from pythonping import ping
from typing import Optional, Tuple, Dict, Any

import subprocess
import netifaces
import speedtest

from .models import SignalCableMeasure, SignalMeasure


class ConnectionDetails:
    """
    This class defines default methods to get the:
    latency, transfer_rate, gateway, speed, connection type, and more
    """

    def __init__(self):
        self.gateways = netifaces.gateways()
        self.default_gateway = self.gateways.get('default', {})

    def get_default_gateway(self) -> Optional[str]:
        if netifaces.AF_INET in self.default_gateway:
            gateway_ip = self.default_gateway[netifaces.AF_INET][0]
            return gateway_ip

    def measure_latency(self) -> Tuple[Optional[float], str]:
        gateway = self.get_default_gateway()
        if gateway:
            result = ping(gateway, count=3)
            return result.rtt_avg_ms, f"Gateway local ({gateway})"

    def measure_transfer_rate(self) -> Tuple[Optional[float], Optional[float]]:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 10**6
        upload_speed = st.upload() / 10**6

        return download_speed, upload_speed

    def get_connection_type(self) -> str:
        gateways = self.gateway
        default_gateway = gateways.get('default', {})

        if netifaces.AF_INET in default_gateway:
            active_interface = default_gateway[netifaces.AF_INET][1]
            return active_interface
        return "Interface not detected"


class SignalMeasureCableUtils(ConnectionDetails):
    model = SignalCableMeasure

    def collect_cable_measurements(self) -> Dict[str, Any]:
        """
        Collect all the measures from the cable connection
        """

        data = {}

        latency, _ = self.measure_latency()
        if latency is not None:
            data['latency'] = latency
        
        download_speed, upload_speed = self.measure_transfer_rate()
        if download_speed is not None:
            data['transfer_rate(download)'] = download_speed
            data['transfer_rate(upload)'] = upload_speed

        connection_type = self.get_connection_type()
        data['connection_type'] = connection_type


class SignalMeasureUtils(ConnectionDetails):
    model = SignalMeasure

    def measure_amplitude():
        ...
    
    def measure_frequency():
        ...
    
    def measure_period():
        ...
