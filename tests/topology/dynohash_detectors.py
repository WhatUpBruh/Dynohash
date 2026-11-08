
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

MGMT_BRIDGE = "dh-mgmt-br"
MGMT_BRIDGE_IP = "172.18.50.1/24"

HOSTS = [
    ("h1", "10.0.0.1", "00:00:00:00:00:01", 1, None),
    ("d1", "10.0.0.11", "00:00:00:00:00:11", 2, "172.18.50.11"),
    ("d2", "10.0.0.12", "00:00:00:00:00:12", 3, "172.18.50.12"),
    ("d3", "10.0.0.13", "00:00:00:00:00:13", 4, "172.18.50.13"),
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
    created_mgmt_interfaces = []
    bridge_created = False

    try:
        info("*** Creating management bridge\n")

        run_command([
            "ip", "link", "add", MGMT_BRIDGE,
            "type", "bridge"
        ])
        bridge_created = True

        run_command([
            "ip", "addr", "add", MGMT_BRIDGE_IP,
            "dev", MGMT_BRIDGE
        ])

        run_command([
            "ip", "link", "set", MGMT_BRIDGE, "up"
        ])

        info("*** Creating DynoHash hosts\n")
        switch_ports = []

        for name, ip, mac, port, mgmt_ip in HOSTS:
            host = net.addHost(name, ip=None)

            host_interface = f"{name}-eth0"
            switch_interface = f"s1-eth{port}"

            run_command([
                "ip", "link", "add",
                host_interface, "type", "veth",
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

            if mgmt_ip is not None:
                mgmt_host = f"{name}-mgmt0"
                mgmt_root = f"{name}-mgmt-br"

                run_command([
                    "ip", "link", "add",
                    mgmt_host, "type", "veth",
                    "peer", "name", mgmt_root
                ])
                created_mgmt_interfaces.append(mgmt_root)

                Intf(mgmt_host, node=host)
                host.setIP(
                    mgmt_ip + "/24",
                    intf=mgmt_host
                )

                run_command([
                    "ip", "link", "set",
                    mgmt_root, "master", MGMT_BRIDGE
                ])

                run_command([
                    "ip", "link", "set",
                    mgmt_root, "up"
                ])

        info("*** Configuring static ARP entries\n")

        for name, _, _, _, _ in HOSTS:
            host = net.get(name)

            for peer_name, peer_ip, peer_mac, _, _ in HOSTS:
                if peer_name == name:
                    continue

                result = host.popen([
                    "ip", "neigh", "replace",
                    peer_ip,
                    "lladdr", peer_mac,
                    "nud", "permanent",
                    "dev", f"{name}-eth0"
                ])

                if result.wait() != 0:
                    raise RuntimeError(
                        "Failed to configure ARP on " + name
                    )

        info("*** Starting DynoHash BMv2 switch\n")

        command = [
            "simple_switch_grpc",
            "--device-id", "0",
            *switch_ports,
            "--thrift-port", "9090",
            P4_JSON,
            "--",
            "--grpc-server-addr",
            "127.0.0.1:50051"
        ]

        os.makedirs(
            os.path.dirname(LOG_PATH),
            exist_ok=True
        )

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
        info("*** Management bridge: 172.18.50.1\n")
        info("*** d1 management: 172.18.50.11\n")
        info("*** d2 management: 172.18.50.12\n")
        info("*** d3 management: 172.18.50.13\n")
        info("*** P4Runtime: 127.0.0.1:50051\n")

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

        for interface in created_mgmt_interfaces:
            subprocess.run(
                ["ip", "link", "del", interface],
                check=False
            )

        if bridge_created:
            subprocess.run(
                ["ip", "link", "del", MGMT_BRIDGE],
                check=False
            )


if __name__ == "__main__":
    setLogLevel("info")
    main()
