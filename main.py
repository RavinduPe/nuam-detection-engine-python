from engine.core import DetectionEngine
from detectors.port_scan import PortScanDetector
from utils.packet_source import start_sniffing
from engine.event_bus import send_event

detectors = [
    PortScanDetector(),
]

engine = DetectionEngine(detectors)

def on_packet(pkt):
    event = engine.handle_packet(pkt)
    if event:
        send_event(event)

start_sniffing(on_packet)