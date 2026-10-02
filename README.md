# Modular Multi-Threaded Network Security Sniffer

A lightweight, object-oriented network security sniffer written in Python using **Scapy**. This tool is designed to run concurrent analyzers across multiple network protocols, providing real-time packet visibility and active threat detection.

---

## Features

- **Object-Oriented Architecture**: Built on a shared abstract base class (`PacketAnalyzer`) for consistent logging, timestamping, and fragment-overlap tracking.
- **Concurrent Multi-Threading**: Runs independent background daemon threads for each protocol analyzer to prevent bottlenecks and packet loss.
- **Actionable Threat Detection**:
  - **ARP Spoofing / Poisoning**: Tracks IP-to-MAC associations and flags sudden changes.
  - **TCP State-Machine Analysis**: Validates state transitions (SYN, SYN-ACK, ACK, FIN, RST) and suppresses false positives on mid-stream captures.
  - **Malformed Packet Checks**: Identifies IP fragmentation overlaps and payload length mismatches.
- **Modular Protocol Support**: Dedicated handlers for TCP, UDP, DNS, DHCP, and ARP traffic.

---

## Project Structure

```text
├── main.py             # Application entry point and thread orchestrator
├── base_analyzer.py    # Abstract base class with shared utility functions
├── tcp_analyze.py      # TCP state-machine and anomaly detection
├── udp_analyze.py      # UDP packet logger
├── dns_analyzer.py     # DNS query and response tracker
├── dhcp_analyze.py     # DHCP lease option parser
├── arp_analyze.py      # ARP table monitor and spoofing detector
└── requirements.txt    # Project dependencies
```

## Usage

# 1. Install dependencies 
pip install -r requirements.txt

# 2. Set local router and interface preferences in main.py

# 3. Run the sniffer with root privileges
sudo python main.py
