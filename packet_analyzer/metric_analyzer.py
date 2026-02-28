from handler.event_handler import EventTypeHandler
from packet_analyzer.base import BaseAnalyzer


class MetricAnalyzer(BaseAnalyzer):
    
    def __init__(self, event_type_handler: EventTypeHandler):
        super().__init__(event_type_handler)
    
    def analyze(self, details, known_devices , metric_data):
        metric_data['total_packets'] = metric_data['total_packets'] + 1
        metric_data['data_sent'] = metric_data['data_sent'] + details['data_sent'] 
        metric_data['total_broadcast_packets'] = metric_data['total_broadcast_packets'] + (1 if details['is_broadcast'] else 0)
        metric_data['total_unicast_packets'] = metric_data['total_unicast_packets'] + (0 if details['is_broadcast'] else 1)
        
        metric_data['arp_requests'] = metric_data['arp_requests'] + (1 if details['packet_type'] == "ARP" and details['operation'] == 1 else 0)
        metric_data['arp_replies'] = metric_data['arp_replies'] + (1 if details['packet_type'] == "ARP" and details['operation'] == 2 else 0)
        metric_data['ip_packets'] = metric_data['ip_packets'] + (1 if details['packet_type'] == "IP" else 0)
        metric_data['tcp_packets'] = metric_data['tcp_packets'] + (1 if details['packet_type'] == "TCP-IP" else 0)
        metric_data['udp_packets'] = metric_data['udp_packets'] + (1 if details['packet_type'] == "UDP" else 0)
        metric_data['icmp_packets'] = metric_data['icmp_packets'] + (1 if details['packet_type'] == "ICMP" else 0)
        metric_data['dns_queries'] = metric_data['dns_queries'] + (1 if details['packet_type'] == "DNS" else 0)
        metric_data['dhcp_packets'] = metric_data['dhcp_packets'] + (1 if details['packet_type'] == "DHCP" else 0)
        metric_data['http_requests'] = metric_data['http_requests'] + (1 if details['packet_type'] == "HTTP" else 0)
        metric_data['tls_handshakes'] = metric_data['tls_handshakes'] + (1 if details['packet_type'] == "TLS" else 0)
        
        active_devices = sum(1 for device in known_devices.values() if device['status'] == 'active')
        metric_data['active_devices'] = active_devices
        
    
    