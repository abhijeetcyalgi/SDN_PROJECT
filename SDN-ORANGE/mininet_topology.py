#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  MININET TOPOLOGY — Packet Drop Simulator                            ║
║  File: mininet_topology.py                                           ║
║                                                                      ║
║  Topology:                                                           ║
║    h1(10.0.0.1) ─┐                                                  ║
║    h2(10.0.0.2) ─┤── s1 ──── s2 ── h4(10.0.0.4)                   ║
║    h3(10.0.0.3) ─┘    └──── s3 ── h5(10.0.0.5)                    ║
║                                                                      ║
║  Controller: Ryu (remote) on 127.0.0.1:6633                         ║
║                                                                      ║
║  Run ORDER:                                                          ║
║    Terminal 1: ryu-manager ryu_controller.py                        ║
║    Terminal 2: sudo python3 mininet_topology.py                     ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import subprocess
import json
from datetime import datetime

# ── Mininet imports ──────────────────────────────────────────────────
try:
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController
    from mininet.topo import Topo
    from mininet.link import TCLink
    from mininet.log import setLogLevel, info
    from mininet.cli import CLI
    from mininet.util import dumpNodeConnections
except ImportError:
    print("[ERROR] Mininet not installed. Run: sudo apt install mininet")
    sys.exit(1)


# ════════════════════════════════════════════════════════════════════
#  CUSTOM TOPOLOGY
# ════════════════════════════════════════════════════════════════════

class PacketDropTopo(Topo):
    """
    3-switch, 5-host partial mesh topology.

    Hosts:
      h1 10.0.0.1/24  ─┐
      h2 10.0.0.2/24  ─┤── s1 (OpenFlow 1.3)
      h3 10.0.0.3/24  ─┘     │
                              ├──── s2 ── h4 10.0.0.4/24
                              └──── s3 ── h5 10.0.0.5/24

    Link specs:
      Host ↔ Switch : 100 Mbps, 5ms delay
      Switch ↔ Switch : 1 Gbps, 2ms delay
    """
    def build(self):
        # ── Switches (OpenFlow 1.3) ──────────────────────────────
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # ── Hosts ────────────────────────────────────────────────
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')

        # ── Host ↔ Switch links ──────────────────────────────────
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='5ms', loss=0)
        self.addLink(h2, s1, cls=TCLink, bw=100, delay='5ms', loss=0)
        self.addLink(h3, s1, cls=TCLink, bw=100, delay='5ms', loss=0)
        self.addLink(h4, s2, cls=TCLink, bw=100, delay='5ms', loss=0)
        self.addLink(h5, s3, cls=TCLink, bw=100, delay='5ms', loss=0)

        # ── Switch ↔ Switch links ────────────────────────────────
        self.addLink(s1, s2, cls=TCLink, bw=1000, delay='2ms', loss=0)
        self.addLink(s1, s3, cls=TCLink, bw=1000, delay='2ms', loss=0)
        self.addLink(s2, s3, cls=TCLink, bw=1000, delay='2ms', loss=0)


# ════════════════════════════════════════════════════════════════════
#  TEST SCENARIOS
# ════════════════════════════════════════════════════════════════════

def run_scenario_1_allowed_vs_blocked(net):
    """
    SCENARIO 1: Allowed vs Blocked
    ─────────────────────────────
    Step 1: Verify h1 can ping h2 (ALLOWED — no drop rule)
    Step 2: Install ICMP drop rule via Ryu API
    Step 3: Verify h1 CANNOT ping h2 (BLOCKED)
    Step 4: Remove rule, verify connectivity restored
    """
    print("\n" + "═"*60)
    print("  SCENARIO 1: ALLOWED vs BLOCKED (ICMP Drop)")
    print("═"*60)
    h1 = net.get('h1')
    h2 = net.get('h2')

    # Step 1: Baseline ping — should work
    print("\n[1] Baseline: h1 → h2 ping (expecting PASS)")
    result = h1.cmd('ping -c 5 -W 1 10.0.0.2')
    _print_ping_result(result, expect_pass=True)

    # Step 2: Install ICMP drop via REST API
    print("\n[2] Installing ICMP DROP rule via Ryu controller API...")
    r = subprocess.run(
        ['curl', '-s', '-X', 'POST', 'http://localhost:5000/api/demo/block_icmp'],
        capture_output=True, text=True)
    print(f"    API response: {r.stdout.strip()}")
    time.sleep(1)  # Let rule propagate

    # Step 3: Ping with drop rule active — should fail
    print("\n[3] With DROP rule: h1 → h2 ping (expecting BLOCKED)")
    result = h1.cmd('ping -c 5 -W 1 10.0.0.2')
    _print_ping_result(result, expect_pass=False)

    # Dump flow table
    print("\n[4] OVS Flow table on s1:")
    ft = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                        capture_output=True, text=True)
    for line in ft.stdout.splitlines():
        if line.strip():
            print(f"    {line.strip()}")

    return _parse_ping(result)


def run_scenario_2_normal_vs_failure(net):
    """
    SCENARIO 2: Normal vs Failure (Cross-switch + isolation)
    ─────────────────────────────────────────────────────────
    Step 1: Normal — h1 iperf to h4 (cross-switch, should work)
    Step 2: Install h3 isolation rule
    Step 3: Failure — h3 cannot reach any host
    Step 4: Normal — h1 still reaches h4 (unaffected)
    """
    print("\n" + "═"*60)
    print("  SCENARIO 2: NORMAL vs FAILURE (Host Isolation)")
    print("═"*60)
    h1 = net.get('h1')
    h3 = net.get('h3')
    h4 = net.get('h4')

    # Step 1: h1 → h4 iperf (normal, cross-switch)
    print("\n[1] Normal: h1 → h4 iperf TCP (cross-switch)")
    h4.cmd('iperf -s -D')
    time.sleep(0.5)
    result = h1.cmd('iperf -c 10.0.0.4 -t 3')
    print(f"    {_parse_iperf(result)}")
    h4.cmd('kill %iperf 2>/dev/null')

    # Step 2: Isolate h3
    print("\n[2] Installing h3 ISOLATION rule (block src=10.0.0.3)...")
    r = subprocess.run(
        ['curl', '-s', '-X', 'POST', 'http://localhost:5000/api/demo/block_h3'],
        capture_output=True, text=True)
    print(f"    API response: {r.stdout.strip()}")
    time.sleep(1)

    # Step 3: h3 → h1 should fail
    print("\n[3] Failure: h3 → h1 ping (expecting BLOCKED)")
    result_h3 = h3.cmd('ping -c 5 -W 1 10.0.0.1')
    _print_ping_result(result_h3, expect_pass=False)

    # Step 4: h1 → h4 still works
    print("\n[4] Normal still: h1 → h4 ping (expecting PASS)")
    result_h1 = h1.cmd('ping -c 5 -W 1 10.0.0.4')
    _print_ping_result(result_h1, expect_pass=True)

    # Flow table on s1
    print("\n[5] OVS Flow table on s1 (post isolation):")
    ft = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                        capture_output=True, text=True)
    for line in ft.stdout.splitlines():
        if line.strip():
            print(f"    {line.strip()}")


def run_performance_analysis(net):
    """
    Measure latency (ping) and throughput (iperf) before/after drop rules.
    """
    print("\n" + "═"*60)
    print("  PERFORMANCE ANALYSIS: Latency & Throughput")
    print("═"*60)
    h1 = net.get('h1')
    h2 = net.get('h2')
    h4 = net.get('h4')

    # Latency: h1 → h2
    print("\n[Latency] h1 → h2 (20 pings)")
    result = h1.cmd('ping -c 20 -W 1 10.0.0.2')
    _print_ping_stats(result)

    # Throughput TCP: h1 → h4
    print("\n[Throughput TCP] h1 → h4 (5 seconds)")
    h4.cmd('iperf -s -D')
    time.sleep(0.3)
    result_tcp = h1.cmd('iperf -c 10.0.0.4 -t 5')
    print(f"  TCP: {_parse_iperf(result_tcp)}")
    h4.cmd('kill %iperf 2>/dev/null')

    # Throughput UDP: h1 → h4
    print("\n[Throughput UDP] h1 → h4 UDP (5 seconds)")
    h4.cmd('iperf -s -u -D')
    time.sleep(0.3)
    result_udp = h1.cmd('iperf -c 10.0.0.4 -u -t 5 -b 10M')
    print(f"  UDP: {_parse_iperf(result_udp)}")
    h4.cmd('kill %iperf 2>/dev/null')

    # Port stats
    print("\n[Port Stats] s1:")
    ps = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-ports', 's1'],
                        capture_output=True, text=True)
    print(ps.stdout[:600])


# ════════════════════════════════════════════════════════════════════
#  UTILITIES
# ════════════════════════════════════════════════════════════════════

def _parse_ping(output):
    """Parse ping output → { sent, received, loss_percent }"""
    for line in output.splitlines():
        if 'packets transmitted' in line:
            parts = line.split(',')
            try:
                return {
                    "sent":         int(parts[0].split()[0]),
                    "received":     int(parts[1].strip().split()[0]),
                    "loss_percent": float(parts[2].strip().split('%')[0])
                }
            except Exception:
                pass
    return {"sent": 0, "received": 0, "loss_percent": 100.0}

def _print_ping_result(output, expect_pass):
    stats = _parse_ping(output)
    passed = stats["loss_percent"] < 50 if expect_pass else stats["loss_percent"] >= 80
    icon = "✓ PASS" if passed else "✗ FAIL"
    print(f"    {icon} | sent={stats['sent']} recv={stats['received']} "
          f"loss={stats['loss_percent']}%")

def _print_ping_stats(output):
    for line in output.splitlines():
        if 'rtt min' in line or 'round-trip' in line:
            print(f"  RTT stats: {line.strip()}")
    stats = _parse_ping(output)
    print(f"  sent={stats['sent']} recv={stats['received']} "
          f"loss={stats['loss_percent']}%")

def _parse_iperf(output):
    for line in output.splitlines():
        if 'Mbits/sec' in line or 'Kbits/sec' in line:
            parts = line.strip().split()
            for i, p in enumerate(parts):
                if 'bits/sec' in p and i > 0:
                    return f"{parts[i-1]} {parts[i]}"
    return "N/A"


# ════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        print("[ERROR] Must run as root: sudo python3 mininet_topology.py")
        sys.exit(1)

    setLogLevel('warning')

    # Clean previous state
    os.system('mn -c 2>/dev/null')
    time.sleep(1)

    print("\n" + "═"*60)
    print("  SDN PACKET DROP SIMULATOR — MININET + RYU")
    print("═"*60)
    print("  Topology: 3 switches (s1, s2, s3) + 5 hosts")
    print("  Controller: Ryu (Remote) on 127.0.0.1:6633")
    print("  Web UI: http://localhost:5000")
    print("═"*60)

    # Connect to Ryu controller (must be running separately)
    topo = PacketDropTopo()
    net  = Mininet(
        topo        = topo,
        controller  = None,
        switch      = OVSKernelSwitch,
        link        = TCLink,
        autoSetMacs = True,
    )

    # Add remote Ryu controller
    c0 = net.addController(
        'c0',
        controller = RemoteController,
        ip         = '127.0.0.1',
        port       = 6633,
    )

    net.start()
    print("\n[✓] Network started. Waiting for Ryu to connect (3s)...")
    time.sleep(3)

    print("\n[✓] Node connections:")
    dumpNodeConnections(net.hosts)

    print("\n[✓] Testing basic connectivity (pingAll)...")
    net.pingAll()

    # Run test scenarios
    run_scenario_1_allowed_vs_blocked(net)
    run_scenario_2_normal_vs_failure(net)
    run_performance_analysis(net)

    print("\n" + "═"*60)
    print("  All scenarios complete. Dropping into Mininet CLI.")
    print("  Web UI still available at http://localhost:5000")
    print("  Type 'exit' to quit.")
    print("═"*60)
    CLI(net)

    net.stop()
    os.system('mn -c 2>/dev/null')


if __name__ == '__main__':
    main()
