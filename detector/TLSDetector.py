from detector.base import Detector
from scapy.all import TCP, IP, Ether
from scapy.layers.tls.all import TLS, TLSClientHello

class TLSDetector(Detector):
    def __init__(self):
        super().__init__(name="TLSDetector", detector_type="TLS")

    def extract_details(self, packet):
        eth_layer = packet.getlayer(Ether)
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)

        tls_layer = packet.getlayer(TLS)

        sni = None
        tls_version = None
        cipher_suites = []

        if packet.haslayer(TLSClientHello):
            client_hello = packet.getlayer(TLSClientHello)

            tls_version = client_hello.version

            if hasattr(client_hello, "ext"):
                for ext in client_hello.ext:
                    if ext.name == "server_name":
                        for server in ext.servernames:
                            sni = server.servername.decode(errors="ignore")

            if hasattr(client_hello, "ciphers"):
                cipher_suites = client_hello.ciphers

        details = {
            "packet_type": "TLS",

            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,

            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,

            "src_port": tcp_layer.sport if tcp_layer else None,
            "dst_port": tcp_layer.dport if tcp_layer else None,

            "tls_version": tls_version,
            "sni": sni,
            "cipher_suites": cipher_suites,

            "data_sent": len(packet)
        }

        return details