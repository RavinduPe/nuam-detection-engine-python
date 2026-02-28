from host_profile import HostProfile
from fingerprint_engine import FingerprintEngine
from oui_loader import OUILoader


class NetworkAnalyzer:
    def __init__(self, oui_csv="oui.csv"):
        self.oui_loader = OUILoader(csv_path=oui_csv)
        self.oui_loader.load()

        self.engine = FingerprintEngine(self.oui_loader)
        self.hosts = {}

    def process_packet(self, packet):
        if not packet.haslayer("Ether") or not packet.haslayer("IP"):
            return

        ip = packet["IP"].src
        mac = packet["Ether"].src

        if ip not in self.hosts:
            self.hosts[ip] = HostProfile(ip, mac)

        fingerprint = self.engine.analyze_packet(packet)

        self.hosts[ip].update(
            manufacturer=fingerprint["manufacturer"],
            os=fingerprint["os"],
            device_type=fingerprint["device_type"],
            score=fingerprint["confidence"]
        )

    def get_hosts(self):
        return {ip: host.to_dict() for ip, host in self.hosts.items()}