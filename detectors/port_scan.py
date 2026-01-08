from detectors.base import Detector
from collections import defaultdict
import time

class PortScanDetector(Detector):

    def __init__(self):
        self.tracker = defaultdict(list)

    def name(self):
        return "Port Scan Detector"

    def process_packet(self, pkt):
        from scapy.layers.inet import TCP, IP

        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src = pkt[IP].src
            port = pkt[TCP].dport
            now = time.time()

            self.tracker[src].append((port, now))
            self.tracker[src] = [
                (p, t) for p, t in self.tracker[src] if now - t < 10
            ]

            ports = {p for p, _ in self.tracker[src]}

            if len(ports) > 10:
                return {
                    "type": "PORT_SCAN",
                    "source": src,
                    "ports": list(ports)
                }
