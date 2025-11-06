from scapy.layers.dot11 import Dot11Beacon
from scapy.all import *
import threading


class SignalStrength:
    """
    Simple class with methods to measure the
    signal
    """
    
    measurements = []
    
    @staticmethod
    def _packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                if hasattr(pkt, 'dBm_AntSignal'):
                    rssi = pkt.dBm_AntSignal
                else:
                    extra = pkt.notdecoded
                    rssi = -(256 - ord(extra[-4:-3]))
                SignalStrength.measurements.append(rssi)
            except:
                SignalStrength.measurements.append(-100)
    
    @classmethod
    def wifi_strength(cls, interface, duration):
        cls.measurements = []
        
        sniff(iface=interface, prn=cls._packet_handler, timeout=duration)
        
        # Return average
        return sum(cls.measurements) / len(cls.measurements) if cls.measurements else -100