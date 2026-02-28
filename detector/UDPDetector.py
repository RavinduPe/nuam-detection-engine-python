from detector.base import Detector
from scapy.all import UDP, IP, Ether


class UDPDetector(Detector):
    def __init__(self):
        super().__init__(name="UDPDetector", detector_type="UDP")

    def extract_details(self, packet):
        if not packet.haslayer(UDP):
            return None

        eth_layer = packet.getlayer(Ether)
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        details = {
            "packet_type": "UDP",
            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,
            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "data_sent": len(packet),
            "is_broadcast": eth_layer.dst == "ff:ff:ff:ff:ff:ff" if eth_layer else False
        }

        return details