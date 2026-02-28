from detector.base import Detector
from scapy.all import TCP, IP, Ether, Raw

class TLSDetector(Detector):
    def __init__(self):
        super().__init__(name="TLSDetector", detector_type="TLS")

    def extract_details(self, packet):
        eth_layer = packet.getlayer(Ether)
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        raw_layer = packet.getlayer(Raw)

        sni = None
        if raw_layer and tcp_layer.dport == 443:
            data = raw_layer.load
            # TLS ClientHello starts with 0x16
            if data[0] == 0x16:
                try:
                    start = data.find(b'\x00\x00')# naive but works in many cases
                    if start != -1:
                        sni = data[start+5:].split(b'\x00', 1)[0].decode(errors="ignore")
                except:
                    sni = None

        details = {
            "packet_type": "TLS",
            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,
            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "src_port": tcp_layer.sport if tcp_layer else None,
            "dst_port": tcp_layer.dport if tcp_layer else None,
            "sni": sni,
            "data_sent": len(packet),
            "is_broadcast": eth_layer.dst == "ff:ff:ff:ff:ff:ff" if eth_layer else False,
        }

        return details