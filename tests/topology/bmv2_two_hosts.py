#!/usr/bin/env python3
"""Two-host Mininet topology connected to a BMv2 P4Runtime switch.

Run with: sudo python3 ~/dynohash/tests/topology/bmv2_two_hosts.py
"""
import os
import signal
import subprocess
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import Intf
from mininet.log import info, setLogLevel
from mininet.net import Mininet

PROJECT = Path(__file__).resolve().parents[2]
P4_JSON = PROJECT / "tests" / "p4" / "forwarding" / "forwarding.json"
LOG_PATH = PROJECT / "logs" / "bmv2-stage6.log"

H1_MAC = "00:00:00:00:00:01"
H2_MAC = "00:00:00:00:00:02"


def run_checked(command):
    subprocess.run(command, check=True)


def host_checked(host, command):
    """Execute a command in a Mininet host and fail if it exits nonzero."""
    output, error, code = host.pexec(*command)
    if code != 0:
        raise RuntimeError(
            f"{host.name}: command {command!r} failed (exit {code}): "
            f"{error or output}"
        )


def main():
    if not P4_JSON.is_file():
        raise FileNotFoundError(f"Compiled P4 pipeline not found: {P4_JSON}")

    net = Mininet(topo=None, build=False, controller=None)
    switch_process = None

    try:
        info("*** Creating Mininet hosts\n")
        h1 = net.addHost("h1", ip="10.0.0.1/24")
        h2 = net.addHost("h2", ip="10.0.0.2/24")

        info("*** Creating virtual Ethernet pairs\n")
        run_checked(["ip", "link", "add", "h1-eth0", "type", "veth",
                     "peer", "name", "s1-eth1"])
        run_checked(["ip", "link", "add", "h2-eth0", "type", "veth",
                     "peer", "name", "s1-eth2"])

        info("*** Attaching interfaces and configuring host addresses\n")
        h1_intf = Intf("h1-eth0", node=h1)
        h2_intf = Intf("h2-eth0", node=h2)
        h1.setMAC(H1_MAC, intf=h1_intf)
        h2.setMAC(H2_MAC, intf=h2_intf)
        h1.setIP("10.0.0.1/24", intf=h1_intf)
        h2.setIP("10.0.0.2/24", intf=h2_intf)
        host_checked(h1, ["ip", "link", "set", "dev", "h1-eth0", "up"])
        host_checked(h2, ["ip", "link", "set", "dev", "h2-eth0", "up"])
        run_checked(["ip", "link", "set", "dev", "s1-eth1", "up"])
        run_checked(["ip", "link", "set", "dev", "s1-eth2", "up"])

        info("*** Adding permanent ARP entries\n")
        host_checked(h1, ["ip", "neigh", "replace", "10.0.0.2",
                          "lladdr", H2_MAC, "nud", "permanent",
                          "dev", "h1-eth0"])
        host_checked(h2, ["ip", "neigh", "replace", "10.0.0.1",
                          "lladdr", H1_MAC, "nud", "permanent",
                          "dev", "h2-eth0"])

        info("*** Starting BMv2 P4Runtime switch\n")
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        command = [
            "simple_switch_grpc", "--device-id", "0",
            "-i", "1@s1-eth1", "-i", "2@s1-eth2",
            "--thrift-port", "9090", str(P4_JSON), "--",
            "--grpc-server-addr", "127.0.0.1:50051",
        ]
        with LOG_PATH.open("w") as log_file:
            switch_process = subprocess.Popen(
                command, stdout=log_file, stderr=subprocess.STDOUT
            )

        time.sleep(3)
        if switch_process.poll() is not None:
            raise RuntimeError(
                f"BMv2 exited early; inspect {LOG_PATH}"
            )

        info("*** h1: 10.0.0.1/24, " + H1_MAC + "\n")
        info("*** h2: 10.0.0.2/24, " + H2_MAC + "\n")
        info("*** BMv2 gRPC: 127.0.0.1:50051\n")
        info("*** BMv2 Thrift: 9090\n")
        info("*** Starting Mininet CLI\n")
        CLI(net)
    finally:
        info("*** Cleaning up\n")
        if switch_process is not None and switch_process.poll() is None:
            switch_process.send_signal(signal.SIGTERM)
            try:
                switch_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                switch_process.kill()
                switch_process.wait()
        net.stop()
        for interface in ("s1-eth1", "s1-eth2"):
            subprocess.run(["ip", "link", "del", interface], check=False,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    setLogLevel("info")
    main()
