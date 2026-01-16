from engine.core import DetectionEngine
from utils.packet_source import start_sniffing
from engine.event_bus import send_event

engine = DetectionEngine()

def on_packet(pkt):
    event = engine.handle_packet(pkt)
    if event:
        send_event(event)

start_sniffing(on_packet)