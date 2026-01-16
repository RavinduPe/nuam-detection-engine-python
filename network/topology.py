import os
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel


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

    ids_port = None
    for port in s1.intfList():
        if port.link:
            if port.link.intf1.node == hIDS or port.link.intf2.node == hIDS:
                ids_port = port.name
                break

    if not ids_port:
        raise Exception("IDS interface not found!")


    os.system(f"""
    ovs-vsctl -- \
    --id=@p get port {ids_port} \
    --id=@m create mirror name=ids-mirror select-all=true output-port=@p \
    set bridge s1 mirrors=@m
    """)

    return net
