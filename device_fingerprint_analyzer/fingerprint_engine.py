from scapy.all import Ether, IP, TCP, DHCP, Raw


class FingerprintEngine:
    def __init__(self, oui_loader):
        self.oui_loader = oui_loader

    def analyze_packet(self, packet):
        result = {
            "manufacturer": "Unknown",
            "os": "Unknown",
            "device_type": "Unknown",
            "confidence": 0
        }

        if Ether in packet:
            mac = packet[Ether].src
            vendor = self.oui_loader.lookup(mac)
            result["manufacturer"] = vendor
            if vendor != "Unknown":
                result["confidence"] += 2

        if IP in packet:
            ttl = packet[IP].ttl
            if ttl >= 120:
                result["os"] = "Windows"
                result["confidence"] += 1
            elif ttl >= 60:
                result["os"] = "Linux/macOS"
                result["confidence"] += 1

        if TCP in packet:
            window = packet[TCP].window
            if window == 64240:
                result["os"] = "Linux"
                result["confidence"] += 2
            elif window == 65535:
                result["os"] = "Windows"
                result["confidence"] += 2

        if DHCP in packet:
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    if opt[0] == "vendor_class_id":
                        if "MSFT" in str(opt[1]):
                            result["os"] = "Windows"
                            result["confidence"] += 3

        if Raw in packet:
            payload = bytes(packet[Raw].load)
            if b"User-Agent" in payload:
                ua = payload.decode(errors="ignore")

                if "Windows" in ua:
                    result["os"] = "Windows"
                    result["confidence"] += 3
                elif "Android" in ua:
                    result["os"] = "Android"
                    result["device_type"] = "Mobile"
                    result["confidence"] += 3
                elif "iPhone" in ua:
                    result["os"] = "iOS"
                    result["device_type"] = "Mobile"
                    result["confidence"] += 3

        vendor = result["manufacturer"]
        if "Cisco" in vendor:
            result["device_type"] = "Network Device"
        elif "HP" in vendor:
            result["device_type"] = "Printer/Desktop"
        elif "Apple" in vendor and result["device_type"] == "Unknown":
            result["device_type"] = "Laptop/Mobile"

        return result