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
            "payload": details
        }
        
        if event_type == "DEVICE_JOINED":
            event["payload"] = self.handle_device_joined_event_type(details)
            event["type"] = self.event__to_state_mapper[event_type]
        else:
            pass
        
        return event
        
    def handle_device_joined_event_type(self , details):
        pass