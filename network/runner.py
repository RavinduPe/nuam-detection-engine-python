
import os
import random
import time
from engine.config import ENABLED_DETECTORS
from engine.core import DetectionEngine
from utils.packet_source import start_sniffing


def generate_test_traffic(net):
    hosts = [net.get(h) for h in ("h1", "h2", "h3", "h4")]

    while True:
        src = random.choice(hosts)
        dst = random.choice([h for h in hosts if h != src])
        print(f"[TRAFFIC] {src.name} {dst.IP()}", flush=True)
        src.cmd(f"ping -c 1 {dst.IP()} > /dev/null 2>&1")
        time.sleep(random.uniform(1, 3))


def start_detection_engine():
    engine = DetectionEngine(ENABLED_DETECTORS)

    def on_packet(pkt):
        packet_type = engine.observe_type(pkt)
        
        if packet_type not in ENABLED_DETECTORS:
            return
        
        observed_details = engine.extract_device_info(pkt, packet_type)
        is_new = engine.is_new_device_joined(observed_details)

        if is_new:
            event = engine.generate_event(
                observed_details,
                detector_name=f"{packet_type} Detector"
            )
            print("New device joined:", event , flush=True)

    start_sniffing(on_packet)