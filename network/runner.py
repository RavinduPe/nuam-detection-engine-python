import random
import time
from engine.config import ENABLED_DETECTORS
from engine.core import DetectionEngine
from engine.config import BACKEND_WS_URL
from utils.packet_source import start_sniffing
from logger.logger import Logger
from handler.event_handler import EventTypeHandler
from handler.data_handler import DataHandler

import random
import time

def generate_test_traffic(net):
    hosts = [net.get(h) for h in ("h1", "h2", "h3", "h4")]

    http_server = hosts[0]
    http_server.cmd("pkill -f http.server")
    http_server.cmd("python3 -m http.server 80 >/dev/null 2>&1 &")

    https_server = hosts[1]
    https_server.cmd("pkill -f s_server")
    https_server.cmd(
        "openssl s_server -accept 443 "
        "-cert /etc/ssl/certs/ssl-cert-snakeoil.pem "
        "-key /etc/ssl/private/ssl-cert-snakeoil.key "
        "-quiet >/dev/null 2>&1 &"
    )

    packet_types = ["ICMP", "TCP", "UDP", "HTTP", "HTTPS", "TLS" , "DHCP"]

    while True:
        src = random.choice(hosts)
        dst = random.choice([h for h in hosts if h != src])
        pkt_type = random.choice(packet_types)

        if pkt_type == "ICMP":
            src.cmd(f"ping -c 1 {dst.IP()} >/dev/null 2>&1")
            print(f"[ICMP] {src.name} -> {dst.name}", flush=True)

        elif pkt_type == "TCP":
            dst.cmd("pkill -f 'nc -l 12345'")
            dst.cmd("nc -l 12345 >/dev/null 2>&1 &")
            src.cmd(f"echo 'test' | nc {dst.IP()} 12345")
            print(f"[TCP] {src.name} -> {dst.name}", flush=True)

        elif pkt_type == "UDP":
            src.cmd(f"echo 'hello' | nc -u {dst.IP()} 9999")
            print(f"[UDP] {src.name} -> {dst.name}", flush=True)

        elif pkt_type == "HTTP":
            src.cmd(f"curl http://{http_server.IP()} >/dev/null 2>&1")
            print(f"[HTTP] {src.name} -> {http_server.name}", flush=True)

        elif pkt_type == "HTTPS":
            src.cmd(f"curl -k https://{https_server.IP()} >/dev/null 2>&1")
            print(f"[HTTPS] {src.name} -> {https_server.name}", flush=True)

        elif pkt_type == "TLS":
            src.cmd(
                f"echo | openssl s_client -connect {https_server.IP()}:443 "
                "-servername example.com >/dev/null 2>&1"
            )
            print(f"[TLS] {src.name} -> {https_server.name}", flush=True)
            
        elif pkt_type == "DHCP":
            # Request a DHCP lease on a random host
            src.cmd("dhclient -v -1 >/dev/null 2>&1")  # -1 means request once
            print(f"[DHCP] {src.name} requesting lease", flush=True)


        time.sleep(random.uniform(1, 3))


def start_detection_engine():
    engine = DetectionEngine(ENABLED_DETECTORS)
    logger = Logger(BACKEND_WS_URL)
    logger.init_socket_connection()
    event_type_handler = EventTypeHandler()
    data_handler = DataHandler(logger , event_type_handler)

    def on_packet(pkt):
        packet_type = engine.observe_type(pkt)
        
        if packet_type not in ENABLED_DETECTORS:
            return
        
        observed_details = engine.extract_device_info(pkt, packet_type)
        data_handler.handle_observed_data(observed_details, packet_type)
                
    start_sniffing(on_packet)