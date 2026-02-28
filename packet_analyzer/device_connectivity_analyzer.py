from datetime import datetime, timezone

from handler.event_handler import EventTypeHandler
from packet_analyzer.base import BaseAnalyzer


class ConnectivityJoinAnalyzer(BaseAnalyzer):
    
    def __init__(self, event_type_handler: EventTypeHandler):
        super().__init__(event_type_handler)
    
    def analyze(self, details, known_devices , metric_data , generate_event):
        self.handle_device_join_event(details , known_devices , metric_data , generate_event)
    
    
    def parse_details(self, details):
        out = {}
        
        if "src_mac" in details:
            out['mac'] =  details['src_mac']
        elif "eth_src" in details:
            out['mac'] = details['eth_src']
        else:
            out['mac'] = 'Unknown'
            
        
        if "src_ip" in details:
            out['ip_address'] = details['src_ip']
        elif "psrc" in details:
            out['ip_address'] = details['psrc']
        else:
            out['ip_address'] = 'Unknown'
            
        out['hostname'] = 'Unknown'
        out['first_seen'] = None
        out['last_seen'] = None
        out['online'] = True
        out['device_type'] = 'Unknown'
        out['vendor'] = 'Unknown'
        out['os'] = 'Unknown'
        out['data_sent'] = 0
        out['data_received'] = 0
        out['status'] = 'active'
        out['access_logs'] = []
        out['access_services'] = []
        return out
    
    def add_known_device(self, mac_address, details, known_devices, metric_data):
        details['first_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        details['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        known_devices[mac_address] = details
        metric_data['total_devices'] += 1
        metric_data['active_devices'] += 1
        
    def handle_device_join_event(self, details , known_devices , metric_data , generate_event):
        mac_address = ""
        if "src_mac" in details:
            mac_address = details['src_mac']
        elif "eth_src" in details:
            mac_address = details['eth_src']
        else:
            mac_address = 'Unknown'
            
        if mac_address == 'Unknown':
            return
                
        parsed_details = self.parse_details(details)
        
        if mac_address in known_devices:
            if known_devices[mac_address]['mac'] == "Unknown":
                known_devices[mac_address].update(parsed_details)
        
            known_devices[mac_address]['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            known_devices[mac_address]['online'] = True
            known_devices[mac_address]['status'] = 'active'
            
                    
        if mac_address not in known_devices:
            self.add_known_device(mac_address, parsed_details, known_devices, metric_data)
            generate_event(parsed_details, "DEVICE_JOINED")
        



class ConnectivityLeaveAnalyzer(BaseAnalyzer):
    
    def __init__(self, event_type_handler: EventTypeHandler):
        super().__init__(event_type_handler)
    
    def analyze(self, details, known_devices , metric_data , generate_event):
        mac_address = ""
        if "src_mac" in details:
            mac_address = details['src_mac']
        elif "eth_src" in details:
            mac_address = details['eth_src']
        else:
            mac_address = 'Unknown'
            
        if mac_address == 'Unknown':
            return
                
        if mac_address in known_devices:
            known_devices[mac_address]['online'] = False
            known_devices[mac_address]['status'] = 'inactive'
            generate_event(known_devices[mac_address], "DEVICE_LEFT")