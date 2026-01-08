import requests

BACKEND_URL = "http://192.168.56.1:5000/api/alert"

def send_event(event):
    try:
        requests.post(BACKEND_URL, json=event, timeout=1)
    except:
        pass