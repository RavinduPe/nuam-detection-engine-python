from threading import Thread
from network.topology import create_lab_network
from network.runner import generate_test_traffic, start_detection_engine
from mininet.log import setLogLevel

if __name__ == "__main__":
    setLogLevel("info")

    net = create_lab_network()

    traffic_thread = Thread(
        target=generate_test_traffic,
        args=(net,),
        daemon=True
    )

    ids_thread = Thread(
        target=start_detection_engine,
        daemon=True
    )

    ids_thread.start()
    traffic_thread.start()

    from mininet.cli import CLI
    CLI(net)

    net.stop()
