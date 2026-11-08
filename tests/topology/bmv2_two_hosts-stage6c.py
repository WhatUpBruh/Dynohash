#!/usr/bin/env python3

import os
import signal
import subprocess
import time

from mininet.net import Mininet
from mininet.node import Host
from mininet.link import Intf
from mininet.cli import CLI
from mininet.log import setLogLevel, info

PROJECT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
P4_JSON = os.path.join(
    PROJECT, "tests/p4/forwarding/forwarding.json"
)

def main():
    net = Mininet(
        topo=None,
        build=False,
        controller=None
    )

    switch_process = None

    try:
        info("*** Creating Mininet hosts\n")

        h1 = net.addHost("h1", ip="10.0.0.1/24")
        h2 = net.addHost("h2", ip="10.0.0.2/24")

        info("*** Creating virtual Ethernet pairs\n")

        subprocess.run(
            ["ip", "link", "add", "h1-eth0",
             "type", "veth", "peer", "name", "s1-eth1"],
            check=True
        )

        subprocess.run(
            ["ip", "link", "add", "h2-eth0",
             "type", "veth", "peer", "name", "s1-eth2"],
            check=True
        )

        info("*** Attaching interfaces to hosts\n")

        h1_intf = Intf("h1-eth0", node=h1)
        h2_intf = Intf("h2-eth0", node=h2)

        h1.setIP("10.0.0.1/24", intf=h1_intf)
        h2.setIP("10.0.0.2/24", intf=h2_intf)

        subprocess.run(
            ["ip", "link", "set", "s1-eth1", "up"],
            check=True
        )
        subprocess.run(
            ["ip", "link", "set", "s1-eth2", "up"],
            check=True
        )

        info("*** Starting BMv2 P4Runtime switch\n")

        command = [
            "simple_switch_grpc",
            "--device-id", "0",
            "-i", "1@s1-eth1",
            "-i", "2@s1-eth2",
            "--thrift-port", "9090",
            P4_JSON,
            "--",
            "--grpc-server-addr", "127.0.0.1:50051"
        ]

        log_path = os.path.join(PROJECT, "logs", "bmv2-stage6.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        log_file = open(log_path, "w")

        try:
            switch_process = subprocess.Popen(
                command,
                stdout=log_file,
                stderr=subprocess.STDOUT
            )
        finally:
            log_file.close()

        time.sleep(3)

        if switch_process.poll() is not None:
            raise RuntimeError(
                "BMv2 exited before Mininet CLI started"
            )

        info("*** Adding static ARP entries\n")

        h1.cmd(
            "arp -s 10.0.0.2 00:00:00:00:00:02"
        )

        h2.cmd(
            "arp -s 10.0.0.1 00:00:00:00:00:01"
        )

        info("*** Starting Mininet CLI\n")
        info("*** BMv2 gRPC: 127.0.0.1:50051\n")
        info("*** BMv2 Thrift: 9090\n")

        CLI(net)

    finally:
        info("*** Cleaning up\n")

        if switch_process is not None:
            switch_process.send_signal(signal.SIGTERM)

            try:
                switch_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                switch_process.kill()
                switch_process.wait()

        net.stop()

        for intf in ["s1-eth1", "s1-eth2"]:
            subprocess.run(
                ["ip", "link", "del", intf],
                check=False
            )

if __name__ == "__main__":
    setLogLevel("info")
    main()
