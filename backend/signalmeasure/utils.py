from scapy.layers.dot11 import Dot11Beacon
from scapy.all import *
import threading


class SignalStrength:
    """
    Simple class with methods to measure the
    signal
    """
    def wifi_strength(interface, duration, pkt):
        measurements = []
        
        if pkt.haslayer(Dot11Beacon):
            try:
                if hasattr(pkt, 'dBm_AntSignal'):
                    rssi = pkt.dBm_AntSignal
                else:
                    extra = pkt.notdecoded
                    rssi = -(256 - ord(extra[-4:-3]))
                measurements.append(rssi)
            except:
                measurements.append(-100)
    
        sniff(ifaces=interface, prn=SignalStrength.wifi_strength, timeout=duration)
        return sum(measurements) / len(measurements) if measurements else -100