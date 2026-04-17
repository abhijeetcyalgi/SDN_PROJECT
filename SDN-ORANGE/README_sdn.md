# SDN Packet Drop Simulator
### Mininet + Ryu Controller + OpenFlow 1.3 — Computer Networks Project

---

## Problem Statement

This project implements an SDN-based **Packet Drop Simulator** using Mininet and a
**Ryu OpenFlow 1.3 controller**. It demonstrates:

- **Controller–switch interaction** via OpenFlow packet_in / flow_mod messages
- **Flow rule design** — match + action (DROP) entries pushed to OVS switches
- **Network behavior observation** — ping, iperf, flow table dumps, Wireshark

The controller implements a **Learning Switch + Firewall** hybrid:
- Learning Switch: learns MAC ↔ port mappings, installs forwarding flows
- Firewall: installs high-priority DROP flows matching src/dst IP, protocol, port

---

## Topology

```
            RYU CONTROLLER (127.0.0.1:6633)
           ╱            │              ╲
    OpenFlow         OpenFlow        OpenFlow
   (control)        (control)       (control)
       │                │                │
  ─────────────    ─────────────    ─────────────
  │  SWITCH s1  │──│  SWITCH s2  │──│  SWITCH s3  │
  │  dpid=1     │  │  dpid=2     │  │  dpid=3     │
  ─────────────    ─────────────    ─────────────
   │    │    │          │                │
   h1   h2   h3         h4              h5

Host IPs:
  h1 = 10.0.0.1/24    h2 = 10.0.0.2/24    h3 = 10.0.0.3/24
  h4 = 10.0.0.4/24    h5 = 10.0.0.5/24

Link specs:
  Host ↔ Switch : 100 Mbps, 5ms delay (TCLink)
  Switch ↔ Switch : 1 Gbps, 2ms delay (TCLink)
```

---

## Files

| File | Description |
|------|-------------|
| `ryu_controller.py` | **Ryu SDN app** — packet_in handler, MAC learning, DROP flow installation, REST API |
| `mininet_topology.py` | **Mininet network** — topology, RemoteController, test scenarios, iperf/ping tests |
| `index.html` | **Web dashboard** — live flow rules, event log, analytics, MAC table, regression tests |
| `README.md` | This file |

---

## Setup and Execution

### Prerequisites

```bash
# System dependencies
sudo apt update
sudo apt install -y mininet openvswitch-switch wireshark tshark iperf

# Python dependencies
pip install ryu flask flask-cors --break-system-packages
```

### Running (requires 2 terminals)

#### Terminal 1 — Start Ryu Controller
```bash
ryu-manager ryu_controller.py --observe-links
```
Expected output:
```
loading app ryu_controller.py
loading app ryu.controller.ofp_handler
PacketDropController: Flask API started on port 5000
```

#### Terminal 2 — Start Mininet Topology
```bash
sudo python3 mininet_topology.py
```
Expected output:
```
[✓] Network started. Waiting for Ryu to connect (3s)...
[✓] Testing basic connectivity (pingAll)...
SCENARIO 1: ALLOWED vs BLOCKED (ICMP Drop)
SCENARIO 2: NORMAL vs FAILURE (Host Isolation)
PERFORMANCE ANALYSIS: Latency & Throughput
```

#### Browser — Open Web Dashboard
```
http://localhost:5000
```

---

## Expected Output

### Scenario 1: Allowed vs Blocked (ICMP)

```
[1] Baseline: h1 → h2 ping (expecting PASS)
    ✓ PASS | sent=5 recv=5 loss=0%

[2] Installing ICMP DROP rule via Ryu controller API...
    API response: {"success": true, ...}

[3] With DROP rule: h1 → h2 ping (expecting BLOCKED)
    ✓ PASS | sent=5 recv=0 loss=100%

[4] OVS Flow table on s1:
    priority=200,ip,icmp actions=drop
    priority=10,in_port=1,eth_dst=... actions=output:2
    priority=0 actions=CONTROLLER:65535
```

### Scenario 2: Normal vs Failure (Host Isolation)

```
[1] Normal: h1 → h4 iperf TCP (cross-switch)
    95.4 Mbits/sec

[2] Installing h3 ISOLATION rule (block src=10.0.0.3)...

[3] Failure: h3 → h1 ping (expecting BLOCKED)
    ✓ PASS | sent=5 recv=0 loss=100%

[4] Normal still: h1 → h4 ping (expecting PASS)
    ✓ PASS | sent=5 recv=5 loss=0%
```

---

## SDN Logic — Controller Design

### packet_in Handler

```python
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, ev):
    # 1. Parse Ethernet/IP/TCP/UDP/ICMP headers
    # 2. Learn MAC: mac_table[dpid][src_mac] = in_port
    # 3. Check DROP rules → if match: install drop flow, discard packet
    # 4. Forward: if dst MAC known → install flow, send; else flood
```

### Drop Flow Installation (OpenFlow 1.3)

```python
# Empty actions list = DROP (OpenFlow semantics)
actions = []
match   = parser.OFPMatch(eth_type=0x0800, ip_proto=1)  # ICMP
mod     = parser.OFPFlowMod(
    datapath     = datapath,
    priority     = 200,       # Higher than forwarding (10)
    match        = match,
    instructions = [OFPInstructionActions(OFPIT_APPLY_ACTIONS, actions)]
)
datapath.send_msg(mod)
```

### Flow Priority Design

| Priority | Rule | Action |
|----------|------|--------|
| 200 | DROP rules (user-defined) | `actions=[]` (drop) |
| 10 | Learned forwarding flows | `actions=[output:port]` |
| 0 | Table-miss | `actions=[output:CONTROLLER]` |

---

## Regression Tests

| ID | Test | Method |
|----|------|--------|
| RT-001 | Switch Connectivity | `len(datapaths) >= 1` |
| RT-002 | Drop Rule Persistence | Rule list count matches |
| RT-003 | MAC Learning | `mac_table` populated |
| RT-004 | Packet-In Events | `pkt_stats["total_in"] >= 0` |
| RT-005 | Rule ID Uniqueness | No duplicate rule_ids |
| RT-006 | Counter Consistency | `fwd + dropped <= total_in` |

---

## OVS Commands Reference

```bash
# View flow table
ovs-ofctl -O OpenFlow13 dump-flows s1

# View port statistics
ovs-ofctl -O OpenFlow13 dump-ports s1

# Manually add drop rule
ovs-ofctl -O OpenFlow13 add-flow s1 priority=200,ip,icmp,actions=drop

# Remove all flows
ovs-ofctl -O OpenFlow13 del-flows s1
```

---

## Wireshark / Capture

```bash
# Capture on s1-eth1 (h1's interface at switch)
sudo tcpdump -i s1-eth1 -n icmp

# Or use Wireshark
sudo wireshark &
# Select interface: s1-eth1
```

---

## References

1. Mininet Documentation — http://mininet.org/walkthrough/
2. Ryu SDN Framework — https://ryu.readthedocs.io/en/latest/
3. OpenFlow 1.3 Specification — https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf
4. Open vSwitch Documentation — https://docs.openvswitch.org/
5. Ryu Simple Switch Example — https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
