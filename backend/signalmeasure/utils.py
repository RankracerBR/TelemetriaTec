import subprocess

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, RadioTap
from scapy.sendrecv import sniff

# TODO: REMOVE PRINTS


class PacketManager:
    """
    class to manage packets and generate
    the informations about the signal
    """

    measurements = []
    rssi = None  # Received Signal Strength Indicator
    frequency = None

    @classmethod
    def _packet_handler(cls, pkt):
        try:
            if cls.rssi is None:
                if hasattr(pkt, "dBm_AntSignal"):
                    rssi = pkt.dBm_AntSignal
                else:
                    rssi = None
                frequency = cls._extract_frequency_from_packet(pkt)
                cls.measurements.append((rssi, frequency))

            if cls.frequency is None:
                frequency = cls._extract_frequency_from_packet(pkt)

            cls.measurements.append((rssi, frequency))

        except Exception as e:
            print(f"ERROR: {e}")
            cls.measurements.append((-100, 2412))

    @classmethod
    def _extract_frequency_from_packet(cls, pkt):
        """
        Method to extract different types of packets
        """
        packet_frequency: list = [Dot11Beacon, RadioTap]

        if pkt.haslayer(packet_frequency):
            if hasattr(packet_frequency, "dBm_AntSignal"):
                cls.rssi = packet_frequency.dBm_AntSignal
            elif hasattr(packet_frequency, "dB_AntSignal"):
                cls.rssi = packet_frequency.dB_AntSignal
            elif hasattr(packet_frequency, "ChannelFrequency"):
                cls.frequency = packet_frequency.ChannelFrequency

            return packet_frequency

        # Extract orther packet layers
        for layer in pkt.layers():
            layer_obj = pkt[layer]

            if hasattr(layer_obj, "frequency"):
                return layer_obj.frequency
            if hasattr(layer_obj, "ChannelFrequency"):
                return layer_obj.ChannelFrequency

        return None


class SignalStrength(PacketManager):
    """
    Simple class with methods to measure the
    signal
    """

    @classmethod
    def _get_available_interfaces(cls):
        """
        Get list of available network interfaces
        """
        try:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True
            )
            interfaces = []

            for line in result.stdout.split("\n"):
                if "state UP" in line or "state UNKNOWN" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        interface = parts[1].strip()
                        if interface and not interface.startswith("lo"):
                            interfaces.append(interface)
            return interfaces
        except Exception:
            return ["eth0"]

    @classmethod
    def wifi_strength(cls, interface, duration):
        try:
            sniff(iface=interface, prn=cls._packet_handler, timeout=duration)
            print(
                f"Interface {interface} not found. Searching for available interfaces..."
            )
            available_interfaces = cls._get_available_interfaces()
            print(f"Available interfaces: {available_interfaces}")

            for alt_interface in available_interfaces:
                print(f"Trying interface: {alt_interface}")
                sniff(
                    iface=alt_interface,
                    prn=cls._packet_handler,
                    timeout=duration,
                    store=False,
                )
                continue

            # Return average
            # amplitudes = [measurement[0] for measurement in cls.measurements]
            # frequencies = [measurement[1] for measurement in cls.measurements]

            amplitudes = [
                m[0] for m in cls.measurements if isinstance(m[0], (int, float))
            ]
            frequencies = [
                m[1] for m in cls.measurements if isinstance(m[1], (int, float))
            ]

            if amplitudes:
                avg_amplitude = sum(amplitudes) / len(amplitudes)
            else:
                avg_amplitude = None

            if frequencies:
                common_frequency = max(set(frequencies), key=frequencies.count)
            else:
                common_frequency = None

            print(f"Captured: {len(cls.measurements)} packets")
            print(f"Average: {avg_amplitude} dBm at {common_frequency} Mhz")

            return avg_amplitude, common_frequency

        except ValueError as e:
            return f"Unavailable to obtain the signal: {e}"
