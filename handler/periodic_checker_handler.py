


from datetime import datetime, timezone
from threading import Event, Thread
import time


class PeriodicCheckerHandler:
    
    def __init__(self):
        self._stop_event = Event()

    
    def periodic_check_for_device_leave(self, known_devices, metric_data, generate_event, idle_seconds=180):
        print("Running periodic check for device leave...")
        current_time = datetime.now(timezone.utc)
        
        if len(known_devices.keys()) == 0:
            return
        
        for mac, details in known_devices.items():
            last_seen_str = details.get('last_seen')
            if last_seen_str:
                last_seen = datetime.strptime(
                    details['last_seen'],
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc)

                elapsed = (current_time - last_seen).total_seconds()
                
                if elapsed > self.timeout_seconds and details['online'] == True :
                    details['online'] = False
                    details['status'] = 'left'  
                    metric_data['active_devices'] -= 1
                    self.handle_device_left_event(mac, known_devices)
                    generate_event(details, "DEVICE_LEFT")
                    
                elif elapsed > idle_seconds and details['status'] != 'idle':
                    details['status'] = 'idle'
                    metric_data['active_devices'] -= 1
                    generate_event(details, "DEVICE_IDLE")
                    
                    
    def handle_device_left_event(self, mac_address , known_devices):
        return self.remove_from_known_devices(mac_address, known_devices)
    
    def remove_from_known_devices(self, mac_address , known_devices):
        if mac_address in known_devices:
            del known_devices[mac_address]
            return True
        return False
    
    def start_periodic_check(self, interval , known_devices, metric_data, generate_event, idle_seconds=180):
        def _periodic_check():
            while not self._stop_event.is_set():
                self.periodic_check_for_device_leave(known_devices, metric_data, generate_event, idle_seconds=idle_seconds)
                time.sleep(interval)
        
        self._check_thread = Thread(target=_periodic_check, daemon=True)
        self._check_thread.start()
        