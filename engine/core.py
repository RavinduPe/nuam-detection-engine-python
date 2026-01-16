import datetime
from scapy.all import sniff, ARP, IP

class DetectionEngine:
    def __init__(self):
        self.known_devices = {}
        
    def observe_type(self, packet):
        if ARP in packet:
            return "ARP"
        elif IP in packet:
            return "IP"
        elif packet.haslayer('TCP'):
            return "TCP"
        elif packet.haslayer('UDP'):
            return "UDP"
        elif packet.haslayer('ICMP'):
            return "ICMP"
        elif packet.haslayer('DNS'):
            return "DNS"
        elif packet.haslayer('HTTP'):
            return "HTTP"
        elif packet.haslayer('TLS'):
            return "TLS"
        return None
    
    
    def extract_device_info(self , packet):
        pass
    
    
    def generate_event(self, details , detector_name):
        
        event = {
            "detector": detector_name,
            "details": details,
            "detected_timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
           
        return event
    