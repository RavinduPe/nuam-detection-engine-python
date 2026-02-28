from datetime import datetime, timezone


class EventTypeHandler:
    
    def __init__(self):
        self.event__to_state_mapper = {
            "DEVICE_JOINED" : "TOPOLOGY"
        }
    
    def handle_event_type(self, event_type, details, seq_number):
        event = {
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "sequence": seq_number,
            },
            "type": "", # STATE | METRIC | TOPOLOGY | HEALTH
            "subtype": event_type,
            "payload": details
        }
        
        if event_type == "DEVICE_JOINED":
            event["payload"] = self.handle_device_joined_event_type(details)
            event["type"] = self.event__to_state_mapper[event_type]
        elif event_type == "DEVICE_IDLE":
            event["type"] = "STATE"
            event["payload"] = self.handle_device_idle_event_type(details)
        elif event_type == "DEVICE_LEFT":
            event["type"] = "TOPOLOGY"
            event["payload"] = self.handle_device_left_event_type(details)
        elif event_type == "PERIODIC_TOPOLOGY_STATE":
            event["type"] = "TOPOLOGY"
            event["payload"] = self.periodic_topology_event_type(details)
        elif event_type == "PERIODIC_METRIC_STATE":
            event["type"] = "METRIC"
            event["payload"] = self.periodic_metric_event_type(details)
            
        return event
        
    def handle_device_joined_event_type(self, details):
        
        event_payload = {
            "event_type": "device_connected",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "device": {
                "device_id": details["mac"],
                "hostname": details["hostname"],
                "ip_address": details["ip_address"],
                "device_type": details["device_type"],
                "os": details["os"],
                "vendor": details["vendor"],
                "first_seen": details["first_seen"],
                "last_seen":  details["last_seen"]
            },
            # "network": {
            #     "interface": details.get("interface"),
            #     "vlan": details.get("vlan"),
            #     "signal_strength": details.get("signal_strength"),  # for Wi-Fi
            #     "connection_type": details.get("connection_type", "wired")
            # }
        }
        
        return event_payload
    
    def handle_device_idle_event_type(self, details):
        
        event_payload = {
            "event_type": "device_idle",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "device": {
                "device_id": details["mac"],
                "hostname": details["hostname"],
                "ip_address": details["ip_address"],
                "device_type": details["device_type"],
                "os": details["os"],
                "vendor": details["vendor"],
                "first_seen": details['first_seen'],
                "last_seen": details["last_seen"]
            }
        }
        
        return event_payload
    
    def handle_device_left_event_type(self, details):
        event_payload = {
            "event_type": "device_disconnected",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "device": {
                "device_id": details["mac"],
                "hostname": details["hostname"],
                "ip_address": details["ip_address"],
                "device_type": details["device_type"],
                "os": details["os"],
                "vendor": details["vendor"],
                "last_seen": details["last_seen"],
                "first_seen": details['first_seen']
            }
        }
        
        return event_payload
    
    def periodic_topology_event_type(self, metric_data , known_devices):
        event_payload = {
            "event_type": "topology_snapshot",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "topology": {
                "devices": list(known_devices.values()),
            }
        }
        
        return event_payload

    def periodic_metric_event_type(self, metric_data):
        event_payload = {
            "event_type": "metric_snapshot",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "metrics": {
                "measure_time": metric_data["measure_time"],
                "total_devices": metric_data["total_devices"],
                "active_devices": metric_data["active_devices"],
                "data_sent": metric_data["data_sent"],
                "data_received": metric_data["data_received"],
                "total_broadcast_packets": metric_data["total_broadcast_packets"],
                "total_unicast_packets": metric_data["total_unicast_packets"],
                "arp_requests": metric_data["arp_requests"],
                "arp_replies": metric_data["arp_replies"],
                "ip_packets": metric_data["ip_packets"],
                "tcp_packets": metric_data["tcp_packets"],
                "udp_packets": metric_data["udp_packets"],
                "icmp_packets": metric_data["icmp_packets"],
                "dns_queries": metric_data["dns_queries"],
                "dhcp_packets": metric_data["dhcp_packets"],
                "http_requests": metric_data["http_requests"],
                "tls_handshakes": metric_data["tls_handshakes"],
                "total_packets": metric_data["total_packets"]
            }
        }
    
        return event_payload