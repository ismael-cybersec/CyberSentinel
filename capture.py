from scapy.all import sniff, IP, TCP, ICMP
import time
from logger import log_alert
from firewall import block_ip

# ==============================
# Configuration
# ==============================

TIME_WINDOW = 5

ICMP_THRESHOLD = 20
SYN_THRESHOLD = 20
SSH_THRESHOLD = 3

# ==============================
# Storage
# ==============================

icmp_counter = {}
syn_counter = {}
ssh_counter = {}

alerted_ips = set()

# ==============================
# ICMP Detection
# ==============================

def detect_icmp(packet, src_ip, current_time):

    if packet[ICMP].type != 8:
        return

    if src_ip not in icmp_counter:
        icmp_counter[src_ip] = []

    icmp_counter[src_ip].append(current_time)

    icmp_counter[src_ip] = [
        t for t in icmp_counter[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    if len(icmp_counter[src_ip]) > ICMP_THRESHOLD:

        if src_ip in alerted_ips:
            return

        alerted_ips.add(src_ip)

        print(f"[⚠️ ALERT] ICMP Flood detected from {src_ip}")
        log_alert(src_ip, "ICMP_FLOOD", 70, "HIGH")
        block_ip(src_ip)

# ==============================
# TCP Detection (SYN + SSH)
# ==============================

def detect_tcp(packet, src_ip, current_time):

    tcp_layer = packet[TCP]
    dst_port = tcp_layer.dport

    # -------- SYN Scan Detection --------
    if tcp_layer.flags == "S":

        if src_ip not in syn_counter:
            syn_counter[src_ip] = []

        syn_counter[src_ip].append(current_time)

        syn_counter[src_ip] = [
            t for t in syn_counter[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        if len(syn_counter[src_ip]) > SYN_THRESHOLD:

            if src_ip in alerted_ips:
                return

            alerted_ips.add(src_ip)

            print(f"[⚠️ ALERT] Possible SYN Scan from {src_ip}")
            log_alert(src_ip, "SYN_SCAN", 60, "MEDIUM")
            block_ip(src_ip)

    # -------- SSH Brute Force Detection --------
    if tcp_layer.flags == "S" and dst_port == 22:

        if src_ip not in ssh_counter:
            ssh_counter[src_ip] = []

        ssh_counter[src_ip].append(current_time)

        ssh_counter[src_ip] = [
            t for t in ssh_counter[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        if len(ssh_counter[src_ip]) > SSH_THRESHOLD:

            if src_ip in alerted_ips:
                return

            alerted_ips.add(src_ip)

            print(f"[🚨 ALERT] SSH Brute Force suspected from {src_ip}")
            log_alert(src_ip, "SSH_BRUTE_FORCE", 85, "CRITICAL")
            block_ip(src_ip)

# ==============================
# Packet Callback
# ==============================

def packet_callback(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    current_time = time.time()

    if packet.haslayer(ICMP):
        detect_icmp(packet, src_ip, current_time)

    if packet.haslayer(TCP):
        detect_tcp(packet, src_ip, current_time)

# ==============================
# Start Capture
# ==============================

def start_capture(interface="enp0s3"):
    print(f"[*] CyberSentinel v2 running on {interface}")
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False,
        filter="ip"
    )
