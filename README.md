# SDN_PROJECT
# SDN Packet Drop Simulator (Ryu + Mininet)

## 📌 Overview

This project implements a **Software Defined Networking (SDN) based packet filtering system** using the Ryu controller and Mininet.
It provides a web-based dashboard to dynamically install flow rules and control network traffic in real time.

The system demonstrates how SDN separates the **control plane** (Ryu controller) and **data plane** (Open vSwitch) to enforce network policies.

---

## 🎯 Problem Statement

Traditional networks rely on static configurations and lack flexibility in enforcing dynamic policies.
This project aims to:

* Build a programmable SDN controller
* Dynamically control traffic (allow/drop)
* Provide a user-friendly interface for rule management

---

## 🏗️ System Architecture

```
Mininet Hosts ↔ Open vSwitch ↔ Ryu Controller ↔ Flask Web UI
```

* **Mininet**: Emulates network topology
* **Open vSwitch (OVS)**: Data plane (flow rules execution)
* **Ryu Controller**: Control plane (decision making)
* **Flask UI**: User interface for rule management

---

## ⚙️ Features

* ✅ MAC learning switch
* ✅ Dynamic flow installation
* ✅ Drop rules (ICMP, TCP, custom)
* ✅ Web-based control panel
* ✅ Real-time statistics
* ✅ OpenFlow 1.3 support

---

## 🧰 Technologies Used

* Python 3.8
* Ryu Controller
* Mininet
* Open vSwitch (OVS)
* Flask
* HTML/CSS/JavaScript

---

## 🚀 Setup Instructions

### 1. Clone Repository

```bash
git clone https://github.com/your-username/SDN-Drop-Sim.git
cd SDN-Drop-Sim
```

---

### 2. Create Virtual Environment

```bash
python3.8 -m venv ryu-env
source ryu-env/bin/activate
```

---

### 3. Install Dependencies

```bash
pip install ryu flask flask-cors eventlet==0.30.2
```

---

### 4. Run Ryu Controller

```bash
ryu-manager ryu_controller.py --observe-links
```

---

### 5. Run Mininet (new terminal)

```bash
sudo mn --topo single,3 --controller remote --switch ovsk
```

---

## 🧪 Execution & Results

### ✅ Test 1: Normal Connectivity

```bash
mininet> pingall
```

✔ Output:

```
0% dropped (6/6 received)
```

---

### 🔴 Test 2: Apply Drop Rule (ICMP)

Use Web UI → **Block All ICMP**

```bash
mininet> pingall
```

❌ Output:

```
100% dropped (0/6 received)
```

---

## 📸 Proof of Execution

### 🔹 Normal Ping (Working)

![Ping Success](screenshots/ping_success.png)

### 🔹 Ping Blocked (After Rule)

![Ping Blocked](screenshots/ping_block.png)

### 🔹 Flow Table

```bash
sudo ovs-ofctl dump-flows s1
```

Example:

```
priority=200, icmp actions=drop
priority=10 actions=output:1
```

### 🔹 Controller Logs

Shows API calls and flow installations.

---

## 📊 Important Note (Drop Counter)

The drop counter may remain **zero** even when packets are blocked.

This is because:

* Drop rules are installed in the switch (data plane)
* Packets are dropped before reaching the controller

> “Once a drop rule is installed, packets are filtered at the switch level, reducing controller load.”

---

## 📁 Project Structure

```
SDN-Drop-Sim/
│
├── ryu_controller.py
├── requirements.txt
├── README.md
├── static/
├── templates/
└── screenshots/
```

---

## 📚 References

* Ryu Documentation: https://ryu.readthedocs.io/
* Mininet Documentation: http://mininet.org/
* OpenFlow 1.3 Specification
* Flask Documentation: https://flask.palletsprojects.com/

---

## 🏁 Conclusion

This project successfully demonstrates:

* SDN-based traffic control
* Dynamic rule enforcement
* Separation of control and data planes

It highlights how modern networks can be made programmable, flexible, and efficient.

---

## 👨‍💻 Author

* Abhijeet
* Computer Networks Lab Project

---
