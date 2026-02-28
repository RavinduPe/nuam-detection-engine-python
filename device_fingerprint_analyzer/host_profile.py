class HostProfile:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.manufacturer = "Unknown"
        self.os = "Unknown"
        self.device_type = "Unknown"
        self.confidence = 0
        self.observations = 0

    def update(self, manufacturer=None, os=None, device_type=None, score=0):
        self.observations += 1

        if manufacturer and manufacturer != "Unknown":
            self.manufacturer = manufacturer
            self.confidence += score

        if os and os != "Unknown":
            self.os = os
            self.confidence += score

        if device_type and device_type != "Unknown":
            self.device_type = device_type
            self.confidence += score

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "manufacturer": self.manufacturer,
            "os": self.os,
            "device_type": self.device_type,
            "confidence": self.confidence,
            "observations": self.observations
        }