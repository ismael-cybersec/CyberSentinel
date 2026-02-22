# CyberSentinel

Behavioral Network Intrusion Detection & Automated Mitigation Engine  
Independent Security Engineering Project  

---

## Overview

CyberSentinel is a lightweight behavioral Network Intrusion Detection and Response (NDR) prototype developed in Python using Scapy.

The system performs real-time packet inspection, detects abnormal traffic patterns, and automatically mitigates threats by dynamically blocking malicious IP addresses using Linux firewall rules.

---

## Features

- Real-time packet capture (Scapy)
- ICMP Flood detection (threshold-based)
- TCP SYN scan detection
- Sliding time window behavioral analysis
- Structured JSON logging
- Automated IP blocking via iptables
- Alert suppression mechanism (anti-alert storm)

---

## Architecture

CyberSentinel follows a modular architecture:

Network Traffic  
→ Packet Capture Module  
→ Detection Engine  
→ Logging Module  
→ Automated Firewall Response  

---

## Detection Logic

### ICMP Flood Detection
- Protocol: ICMP
- Type: Echo Request (Type 8)
- Threshold: 20 packets
- Time Window: 5 seconds
- Severity: HIGH

### SYN Scan Detection
- Protocol: TCP
- Flag: SYN (without ACK)
- Threshold: 20 packets
- Time Window: 5 seconds
- Severity: MEDIUM

---

## Automated Mitigation

When malicious behavior is detected, CyberSentinel automatically applies a firewall rule:

iptables -A INPUT -s <malicious_ip> -j DROP

This prevents further traffic from the attacker.

---

## Installation

Clone the repository:

git clone https://github.com/ismael-cybersec/CyberSentinel.git  
cd CyberSentinel  

Install dependencies:

pip install -r requirements.txt  

Run the engine (requires root privileges):

sudo python3 main.py  

---

## Project Status

CyberSentinel v1 – Functional Behavioral IDS with Automated Mitigation  

Future improvements include:
- Stateful flow tracking
- SSH brute-force detection
- Threat scoring system
- Web-based monitoring dashboard
- Anomaly-based ML detection

---

## Author

Ismael Abdallah Baby 
Cybersecurity Student & Network Security Enthusiast  
  

© 2026 Ismael Abdallah Baby All rights reserved.
