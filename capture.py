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

# ==============================
# Storage
# ==============================

icmp_counter = {}
syn_counter = {}

# Prevent alert storm
alerted_ips = set()

# ==============================
# ICMP Detection
# ==============================

def detect_icmp(packet, src_ip, current_time):

    icmp_layer = packet[ICMP]

    # Only detect Echo Request (Type 8)
    if icmp_layer.type != 8:
        return

    if src_ip not in icmp_counter:
        icmp_counter[src_ip] = []

    icmp_counter[src_ip].append(current_time)

    # Keep timestamps inside sliding window
    icmp_counter[src_ip] = [
        t for t in icmp_counter[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    count = len(icmp_counter[src_ip])

    if count > ICMP_THRESHOLD:

        if src_ip in alerted_ips:
            return

        alerted_ips.add(src_ip)

        threat_score = 70
        severity = "HIGH"

        print(f"[⚠️ ALERT] ICMP Flood detected from {src_ip}")
        log_alert(src_ip, "ICMP_FLOOD", threat_score, severity)
        block_ip(src_ip)


# ==============================
# SYN Scan Detection
# ==============================

def detect_syn(packet, src_ip, current_time):

    tcp_layer = packet[TCP]

    # Detect SYN without ACK
    if tcp_layer.flags == "S":

        if src_ip not in syn_counter:
            syn_counter[src_ip] = []

        syn_counter[src_ip].append(current_time)

        # Keep timestamps inside sliding window
        syn_counter[src_ip] = [
            t for t in syn_counter[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        count = len(syn_counter[src_ip])

        if count > SYN_THRESHOLD:

            if src_ip in alerted_ips:
                return

            alerted_ips.add(src_ip)

            threat_score = 60
            severity = "MEDIUM"

            print(f"[⚠️ ALERT] Possible SYN Scan from {src_ip}")
            log_alert(src_ip, "SYN_SCAN", threat_score, severity)
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
        detect_syn(packet, src_ip, current_time)


# ==============================
# Start Capture
# ==============================

def start_capture(interface="enp0s3"):
    print(f"[*] CyberSentinel running on {interface}")
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False,
     
   filter="ip"
    )
