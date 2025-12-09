from typing import Any, Dict, Optional, Tuple

import netifaces
import speedtest
from pythonping import ping
from scapy.all import *

from .models import SignalCableMeasure, SignalMeasure


class ConnectionDetails:
    """
    This class defines default methods to get the:
    latency, transfer_rate, gateway, speed, connection type, and more
    """

    def __init__(self):
        self.gateways = netifaces.gateways()
        self.default_gateway = self.gateways.get("default", {})

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

        # Mede download e upload
        download_bps = st.download()
        upload_bps = st.upload()

        # Converte para Mbps
        download_mbps = download_bps / 1_000_000
        upload_mbps = upload_bps / 1_000_000

        return download_mbps, upload_mbps

    def get_connection_type(self) -> str:
        gateways = self.gateways
        default_gateway = gateways.get("default", {})

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
            data["latency"] = latency

        download_speed = self.measure_transfer_rate()
        upload_speed = self.measure_transfer_rate()
        if download_speed is not None:
            data["transfer_rate(download)"] = download_speed

        if upload_speed is not None:
            data["transfer_rate(upload)"] = upload_speed

        connection_type = self.get_connection_type()
        data["connection_type"] = connection_type


class SignalMeasureUtils(ConnectionDetails):
    model = SignalMeasure

    def measure_amplitude(): ...

    def measure_frequency(): ...

    def measure_period(): ...
