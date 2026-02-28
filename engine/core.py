from scapy.all import ARP, IP, TCP, UDP, ICMP, DNS, BOOTP, DHCP

class DetectionEngine:
    def __init__(self, detectors):
        """
        detectors: dict mapping packet_type -> Detector instance
        e.g., detectors = {
            "ARP": ARPDetector(),
            "IP": IPDetector(),
            "TCP-IP": TCPIPDetector(),
            "UDP": UDPDetector(),
            "ICMP": ICMPDetector(),
            "DNS": DNSDetector(),
            "DHCP": DHCPDetector(),
            "TLS": TLSDetector(),
            "SMB": SMBDetector()
        }
        """
        self.detectors = detectors

    def observe_types(self, packet):
        """
        Return a list of detected protocol types for this packet.
        Layer-based detection (non-exclusive).
        """

        types = []

        if ARP in packet:
            types.append("ARP")

        if IP in packet:
            types.append("IP")

        if TCP in packet:
            types.append("TCP-IP")

        if UDP in packet:
            types.append("UDP")
            
            udp_layer = packet[UDP]
            if (udp_layer.sport == 67 or udp_layer.sport == 68 or
                udp_layer.dport == 67 or udp_layer.dport == 68):
                types.append("DHCP")

            if DHCP in packet or BOOTP in packet:
                types.append("DHCP")

        if ICMP in packet:
            types.append("ICMP")

        if DNS in packet:
            types.append("DNS")

        if TCP in packet:
            try:
                payload = bytes(packet[TCP].payload)
                if len(payload) >= 3:
                    if payload[0] == 0x16 and payload[1] == 0x03:
                        types.append("TLS")
            except Exception:
                pass

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in (139, 445) or dport in (139, 445):
                types.append("SMB")

        return types

    def extract_device_info(self, packet, observed_type):
        """
        Extract packet details using the specific detector instance
        """
        if observed_type not in self.detectors:
            return None, observed_type

        details = self.detectors[observed_type].extract_details(packet)
        return details, observed_type