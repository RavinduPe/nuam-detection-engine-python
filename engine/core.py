
class DetectionEngine:
    def __init__(self, detectors):
        self.detectors = detectors
        
    def handle_packets(self, packet):
        for detector in self.detectors:
            results = detector.process_packet(packet)
            return results