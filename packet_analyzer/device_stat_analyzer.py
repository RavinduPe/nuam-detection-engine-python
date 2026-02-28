
from datetime import datetime, timezone

from handler.event_handler import EventTypeHandler
from logger.logger import Logger


class DeviceStatAnalyzer:
    
    def __init__(self, event_type_handler: EventTypeHandler):
        self.event_type_handler = event_type_handler
        
    def analyze(self, details, known_devices):
        
        """Analyze device statistics and update metrics."""
        source_mac_address = details['eth_src'] or 'Unknown'
        dest_mac_address =  details['eth_dst'] or 'Unknown'
        
        if source_mac_address == 'Unknown' or source_mac_address not in known_devices:
            return
        
        if dest_mac_address == 'Unknown' or dest_mac_address not in known_devices:
            known_devices[source_mac_address]['active'] = True
            known_devices[source_mac_address]['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            known_devices[source_mac_address]['data_sent'] = known_devices[source_mac_address]['data_sent'] + details['data_sent']
            return
        
        known_devices[source_mac_address]['packet_count'] = known_devices[source_mac_address]['packet_count'] + 1
        known_devices[source_mac_address]['data_sent'] = known_devices[source_mac_address]['data_sent'] + details['data_sent']
        known_devices[source_mac_address]['active'] = True
        known_devices[source_mac_address]['last_seen'] =  datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        known_devices[dest_mac_address]['data_received'] = known_devices[dest_mac_address]['data_received'] + details['data_sent']