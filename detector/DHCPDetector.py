from detector.base import Detector
from scapy.all import DHCP, BOOTP, Ether, IP, UDP

class DHCPDetector(Detector):
    def __init__(self):
        super().__init__(name="DHCPDetector", detector_type="DHCP")

    def extract_details(self, packet):
        dhcp_layer = packet.getlayer(DHCP)
        bootp_layer = packet.getlayer(BOOTP)
        eth_layer = packet.getlayer(Ether)
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        dhcp_type_map = {
            1: "Discover",
            2: "Offer",
            3: "Request",
            4: "Decline",
            5: "ACK",
            6: "NAK",
            7: "Release",
            8: "Inform"
        }

        message_type = None
        hostname = None
        requested_ip = None
        server_id = None


        for option in dhcp_layer.options:
            if isinstance(option, tuple):
                if option[0] == "message-type":
                    message_type = dhcp_type_map.get(option[1], option[1])
                elif option[0] == "hostname":
                    hostname = option[1].decode(errors="ignore") if isinstance(option[1], bytes) else option[1]
                elif option[0] == "requested_addr":
                    requested_ip = option[1]
                elif option[0] == "server_id":
                    server_id = option[1]

        details = {
            "packet_type": "DHCP",

            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,

            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,

            "src_port": udp_layer.sport if udp_layer else None,
            "dst_port": udp_layer.dport if udp_layer else None,

            "client_mac": bootp_layer.chaddr[:6].hex(":") if bootp_layer else None,
            "your_ip": bootp_layer.yiaddr if bootp_layer else None,
            "transaction_id": bootp_layer.xid if bootp_layer else None,

            "dhcp_message_type": message_type,
            "hostname": hostname,
            "requested_ip": requested_ip,
            "server_identifier": server_id,

            "data_sent": len(packet)
        }

        return details