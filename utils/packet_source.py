from scapy.all import sniff

def start_sniffing(callback):
    sniff(prn=callback, store=False)