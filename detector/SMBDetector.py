from detector.base import Detector
from scapy.all import TCP, IP, Ether, Raw


class SMBDetector(Detector):
    def __init__(self):
        super().__init__(name="SMBDetector", detector_type="SMB")

    def extract_details(self, packet):
        eth_layer = packet.getlayer(Ether)
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        raw_layer = packet.getlayer(Raw)

        
        is_smb = False
        smb_command = None

        if tcp_layer:
        
            if tcp_layer.dport in [445, 139] or tcp_layer.sport in [445, 139]:
                is_smb = True

        
        if raw_layer:
            payload = bytes(raw_layer.load)
            if payload.startswith(b"\xffSMB") or payload.startswith(b"\xfeSMB"):
                is_smb = True
                smb_command = payload[4] if len(payload) > 4 else None

        if not is_smb:
            return None

        details = {
            "packet_type": "SMB",
            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,
            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "src_port": tcp_layer.sport if tcp_layer else None,
            "dst_port": tcp_layer.dport if tcp_layer else None,
            "smb_command": smb_command,
            "data_sent": len(packet),
            "is_broadcast": (
                eth_layer.dst == "ff:ff:ff:ff:ff:ff"
                if eth_layer else False
            ),
        }

        return details