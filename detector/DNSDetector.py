from detector.base import Detector
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether

class DNSDetector(Detector):
    def __init__(self):
        super().__init__(name="DNSDetector", detector_type="DNS")

    def extract_details(self, packet):
        dns_layer = packet.getlayer(DNS)
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        eth_layer = packet.getlayer(Ether)


        is_response = dns_layer.qr == 1

        query_name = None
        query_type = None
        answers = []

        if dns_layer.qd:
            query_name = dns_layer.qd.qname.decode(errors="ignore")
            query_type = dns_layer.qd.qtype

        if is_response and dns_layer.an:
            for i in range(dns_layer.ancount):
                answer = dns_layer.an[i]
                if isinstance(answer, DNSRR):
                    answers.append({
                        "name": answer.rrname.decode(errors="ignore"),
                        "type": answer.type,
                        "rdata": str(answer.rdata)
                    })

        details = {
            "eth_src": eth_layer.src if eth_layer else None,
            "eth_dst": eth_layer.dst if eth_layer else None,
            "eth_type": eth_layer.type if eth_layer else None,
            
            "packet_type": "DNS",
            "transaction_id": dns_layer.id,
            "is_response": is_response,
            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "src_port": udp_layer.sport if udp_layer else None,
            "dst_port": udp_layer.dport if udp_layer else None,
            "query_name": query_name,
            "query_type": query_type,
            "answers": answers,
            "data_sent": len(packet)
        }

        return details