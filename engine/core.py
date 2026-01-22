from scapy.all import ARP, IP

class DetectionEngine:
    def __init__(self , detectors):
        self.detectors = detectors
        
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
    
    
    def extract_device_info(self , packet , observed_type):
        details = self.detectors[observed_type].extract_details(packet)
        return details , observed_type