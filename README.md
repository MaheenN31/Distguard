# Distguard
# 🔐 Distributed Malicious Traffic Detection System

A C++-based distributed computing project that simulates network traffic and distributes it to multiple child nodes for parallel malicious activity detection. This system mimics how real-world IDS (Intrusion Detection Systems) can work across distributed environments.

---

## 🧠 Overview

This project is designed to:
- **Simulate network traffic** with potentially malicious patterns.
- **Distribute the traffic** from a **Main Node** to multiple **Child Nodes**.
- **Analyze traffic in parallel** across child nodes for threats using defined rules.
- **Aggregate the results** back at the Main Node.

---

## 📂 Project Structure

```
distguard/
│
├── common/
│   ├── shared.h              # Packet structure & serialization
│   ├── rules.h               # TrafficAnalyzer for detecting malicious behavior
│   ├── traffic_simulator.h   # Header for traffic simulation
│   └── traffic_simulator.cpp # Generates simulated network packets
│
├── main_node/
│   └── main_node.cpp         # Distributes packets to child nodes and receives reports
│
├── child_node/
│   └── child_node.cpp        # Connects to main node, analyzes packets, returns results
│
└── README.md
```

---

## 🚀 How It Works

1. **Main Node** listens for a fixed number of client connections (child nodes).
2. After connection, it generates synthetic traffic using random payloads, IPs, and ports.
3. It splits the traffic and sends chunks to each **Child Node**.
4. Each **Child Node** uses `TrafficAnalyzer` to:
   - Detect suspicious ports (like 6667, 31337).
   - Scan for malicious keywords in packet payloads (like “trojan”, “virus”).
   - Flag IPs sending too many packets.
5. Each **Child Node** sends its findings back to the **Main Node**.
6. The **Main Node** logs results from each client.

---

## ⚙️ Prerequisites

- C++11 or later
- [Boost C++ Libraries](https://www.boost.org/) (specifically `Boost.Asio`)
- Windows OS (project configured for Windows networking)

---

## 🛠️ Build Instructions

> Replace `C:\path\to\boost` with the actual path to your Boost installation.

### 1. Compile `main_node`

```bash
g++ main_node/main_node.cpp common/traffic_simulator.cpp -I common -IC:\path\to\boost -lws2_32 -o main_node.exe
```

### 2. Compile `child_node`

```bash
g++ child_node/child_node.cpp -I common -IC:\path\to\boost -lws2_32 -o child_node.exe
```

---

## 🧪 Running the Project

### Step-by-step

1. **Start the Main Node**

```bash
main_node.exe
```

2. **In separate terminals**, run the required number of child nodes (3 by default):

```bash
child_node.exe
child_node.exe
child_node.exe
```

3. Observe the communication. Each child node will receive 10 packets, analyze them, and return results.

---

## 🔍 Sample Output

```
[MainNode] Waiting for clients on port 5555...
[MainNode] Client 1 connected.
[MainNode] Client 2 connected.
[MainNode] Client 3 connected.
[MainNode] Sending 10 packets to Client 1...
[Client 1 Response] Total: 10, Malicious: 3
```

---

## ✅ Detection Rules

Implemented in `rules.h`, the following logic flags packets as malicious:

- 🚫 Destination Port is **23**, **6667**, or **31337**
- 🧬 Payload contains keywords: `malware`, `exploit`, `virus`, `trojan`
- 🧨 IP sends **more than 10 packets**

---

## 📌 TODO

- [ ] Support dynamic number of clients
- [ ] Save logs to file
- [ ] Add CLI arguments for port and traffic size
- [ ] Add GUI dashboard for results (Qt)
