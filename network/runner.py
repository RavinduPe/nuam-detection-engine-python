
import os
import time

from engine.config import ENABLED_DETECTORS
from engine.core import DetectionEngine
from utils.packet_source import start_sniffing

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel



def generate_test_traffic():
    
    TARGET_IP = "10.0.0.2"

    while True:
        os.system(f"ping -c 1 {TARGET_IP} > /dev/null 2>&1")
        os.system(f"arping -c 1 {TARGET_IP} > /dev/null 2>&1")
        time.sleep(2)



def start_detection_engine():
    engine = DetectionEngine(ENABLED_DETECTORS)

    def on_packet(pkt):
        packet_type = engine.observe_type(pkt)
        
        if packet_type not in ENABLED_DETECTORS:
            print("Unsupported packet type:", packet_type)
            return
        
        observed_details = engine.extract_device_info(pkt, packet_type)
        is_new = engine.is_new_device_joined(observed_details)

        if is_new:
            event = engine.generate_event(
                observed_details,
                detector_name=f"{packet_type} Detector"
            )
            print("New device joined:", event)

    start_sniffing(on_packet)



def create_lab_network():
    net = Mininet(
        controller=Controller,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    print("*** Adding controller")
    net.addController('c0')

    print("*** Adding switch")
    s1 = net.addSwitch('s1')

    print("*** Adding LAN hosts")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')

    print("*** Adding IDS host (monitoring)")
    hIDS = net.addHost('hIDS', ip='10.0.0.100/24')

    print("*** Creating links")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(hIDS, s1)

    print("*** Starting network")
    net.start()

    print("*** Configuring port mirroring")

    # Find IDS port name on switch
    ids_port = None
    for port in s1.intfList():
        if port.link:
            if port.link.intf1.node == hIDS or port.link.intf2.node == hIDS:
                ids_port = port.name
                break

    if not ids_port:
        raise Exception("IDS interface not found!")

    # Create mirror
    os.system(f"""
    ovs-vsctl -- \
    --id=@p get port {ids_port} \
    --id=@m create mirror name=ids-mirror select-all=true output-port=@p \
    set bridge s1 mirrors=@m
    """)

    print(f"*** Traffic mirrored to {ids_port}")

    print("*** Testing connectivity")
    net.pingAll()

    print("*** Mininet CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

