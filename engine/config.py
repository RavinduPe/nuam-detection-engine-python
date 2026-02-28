from detector.ARPDetector import ARPDetector
from detector.IPDetector import IPDetector
from detector.TCPIPDetector import TCPIPDetector
from detector.TLSDetector import TLSDetector
from detector.DHCPDetector import DHCPDetector
from detector.ICMPDetector import ICMPDetector
from detector.SMBDetector import SMBDetector
from detector.DNSDetector import DNSDetector
from detector.UDPDetector import UDPDetector
import os



ENABLED_DETECTORS = {
    "ARP": ARPDetector(),
    "IP": IPDetector(),
    "TCP-IP": TCPIPDetector(),
    "TLS": TLSDetector(),
    "DHCP": DHCPDetector(),
    "ICMP": ICMPDetector(),
    "SMB": SMBDetector(),
    "DNS": DNSDetector(),
    "UDP": UDPDetector()
}

BACKEND_WS_URL = os.getenv("BACKEND_WS_URL", "ws://192.168.56.1:8000/ws/device")
LOG_PATH = os.getenv("LOG_PATH", "/media/sf_shared/logs.txt")