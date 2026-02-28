from detector.base import Detector
from scapy.all import ICMP, IP, Ether

class ICMPDetector(Detector):
    def __init__(self):
        super().__init__(name="ICMPDetector", detector_type="ICMP")

    def extract_details(self, packet):
        icmp_layer = packet.getlayer(ICMP)
        ip_layer = packet.getlayer(IP)
        eth_layer = packet.getlayer(Ether)

        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code

        icmp_type_map = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded"
        }

        details = {
            "packet_type": "ICMP",

            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,
            "eth_type": eth_layer.type if eth_layer else None,

            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "ttl": ip_layer.ttl if ip_layer else None,

            "icmp_type": icmp_type,
            "icmp_type_name": icmp_type_map.get(icmp_type, "Other"),
            "icmp_code": icmp_code,
            "identifier": getattr(icmp_layer, "id", None),
            "sequence": getattr(icmp_layer, "seq", None),
            "is_broadcast": eth_layer.dst == "ff:ff:ff:ff:ff:ff" if eth_layer else False,
            "data_sent": len(packet)
        }

        return details