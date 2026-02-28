from detector.base import Detector
from scapy.all import IP, TCP, Ether

class TCPIPDetector(Detector):
    def __init__(self):
        super().__init__(name="TCPIPDetector", detector_type="TCP-IP")
        
    def extract_details(self, packet):
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        eth = packet.getlayer(Ether)

        if not ip_layer or not tcp_layer:
            return None

        details = {
            "packet_type": "TCP-IP",

            # Layer 2
            "eth_src": eth.src if eth else None,
            "eth_dst": eth.dst if eth else None,

            # Layer 3
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "version": ip_layer.version,
            "ihl": ip_layer.ihl,
            "tos": ip_layer.tos,
            "len": ip_layer.len,
            "id": ip_layer.id,
            "ip_flags": ip_layer.flags,
            "frag": ip_layer.frag,
            "ttl": ip_layer.ttl,
            "proto": ip_layer.proto,
            "chksum_ip": ip_layer.chksum,
            "options": ip_layer.options if ip_layer.options else [],

            # Layer 4
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "dataofs": tcp_layer.dataofs,
            "reserved": tcp_layer.reserved,
            "tcp_flags": tcp_layer.flags,
            "window": tcp_layer.window,
            "chksum_tcp": tcp_layer.chksum,
            "urgptr": tcp_layer.urgptr,

            # Misc
            "is_broadcast": eth.dst == "ff:ff:ff:ff:ff:ff" if eth else False,
            "data_sent": len(packet)
        }

        return details