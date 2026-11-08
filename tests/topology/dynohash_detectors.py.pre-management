
#!/usr/bin/env python3

import os
import signal
import subprocess
import time

from mininet.net import Mininet
from mininet.link import Intf
from mininet.cli import CLI
from mininet.log import info, setLogLevel

PROJECT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

P4_JSON = os.path.join(PROJECT, "p4", "dynohash.json")
LOG_PATH = os.path.join(PROJECT, "logs", "bmv2-stage7.log")

HOSTS = [
    # Host name, IP, MAC, switch port
    ("h1", "10.0.0.1", "00:00:00:00:00:01", 1),
    ("d1", "10.0.0.2", "00:00:00:00:00:02", 2),
    ("d2", "10.0.0.3", "00:00:00:00:00:03", 3),
    ("d3", "10.0.0.4", "00:00:00:00:00:04", 4),
]


def run_command(command):
    subprocess.run(command, check=True)


def main():
    if not os.path.isfile(P4_JSON):
        raise FileNotFoundError(
            "Compiled P4 pipeline not found: " + P4_JSON
        )

    net = Mininet(topo=None, build=False, controller=None)
    switch_process = None
    created_switch_interfaces = []

    try:
        info("*** Creating DynoHash hosts\n")

        switch_ports = []

        for name, ip, mac, port in HOSTS:
            host = net.addHost(name, ip=None)

            host_interface = f"{name}-eth0"
            switch_interface = f"s1-eth{port}"

            info(f"*** Connecting {name} to port {port}\n")

            run_command([
                "ip", "link", "add",
                host_interface,
                "type", "veth",
                "peer", "name", switch_interface
            ])

            created_switch_interfaces.append(switch_interface)

            intf = Intf(host_interface, node=host)

            host.setIP(ip + "/24", intf=intf)
            host.setMAC(mac, intf=intf)

            run_command([
                "ip", "link", "set",
                switch_interface, "up"
            ])

            switch_ports.extend([
                "-i", f"{port}@{switch_interface}"
            ])

        info("*** Configuring static ARP entries\n")

        for name, _, _, _ in HOSTS:
            host = net.get(name)

            for peer_name, peer_ip, peer_mac, _ in HOSTS:
                if peer_name == name:
                    continue

                # Execute inside the host network namespace.
                # Fail immediately if neighbor configuration fails.
                result = host.popen([
                    "ip", "neigh", "replace",
                    peer_ip,
                    "lladdr", peer_mac,
                    "nud", "permanent",
                    "dev", f"{name}-eth0"
                ])
                if result.wait() != 0:
                    raise RuntimeError(
                        f"Failed to configure ARP on {name}"
                    )

        info("*** Starting DynoHash BMv2 switch\n")

        command = [
            "simple_switch_grpc",
            "--device-id", "0",
            *switch_ports,
            "--thrift-port", "9090",
            P4_JSON,
            "--",
            "--grpc-server-addr", "127.0.0.1:50051"
        ]

        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

        with open(LOG_PATH, "w") as log_file:
            switch_process = subprocess.Popen(
                command,
                stdout=log_file,
                stderr=subprocess.STDOUT
            )

        time.sleep(3)

        if switch_process.poll() is not None:
            raise RuntimeError(
                "BMv2 exited unexpectedly. Check " + LOG_PATH
            )

        info("*** DynoHash topology ready\n")
        info("*** h1: traffic generator, port 1\n")
        info("*** d1: detector A, port 2\n")
        info("*** d2: detector B, port 3\n")
        info("*** d3: detector C, port 4\n")
        info("*** P4Runtime: 127.0.0.1:50051\n")
        info("*** BMv2 log: " + LOG_PATH + "\n")

        CLI(net)

    finally:
        info("*** Cleaning up DynoHash topology\n")

        if switch_process is not None:
            if switch_process.poll() is None:
                switch_process.send_signal(signal.SIGTERM)

            try:
                switch_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                switch_process.kill()
                switch_process.wait()

        net.stop()

        for interface in created_switch_interfaces:
            subprocess.run(
                ["ip", "link", "del", interface],
                check=False
            )


if __name__ == "__main__":
    setLogLevel("info")
    main()
