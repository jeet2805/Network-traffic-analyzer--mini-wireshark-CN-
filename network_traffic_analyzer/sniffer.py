from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import csv

# Counters
proto_stats = defaultdict(int)
src_ip_stats = defaultdict(int)

# CSV setup
log_file = open("logs.csv", mode="w", newline="")
logger = csv.writer(log_file)
logger.writerow(("Time", "Src IP", "Dst IP", "Protocol"))


def detect_protocol(pkt):
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    return "OTHER"


packet_seen = 0


def handle_packet(pkt):
    global packet_seen

    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = detect_protocol(pkt)

    proto_stats[proto] += 1
    src_ip_stats[src_ip] += 1
    packet_seen += 1

    # Throttled console output
    if packet_seen % 3 == 0:
        print(f"{src_ip:<16} -> {dst_ip:<16} | {proto}")

    timestamp = datetime.now().strftime("%H:%M:%S")
    logger.writerow([timestamp, src_ip, dst_ip, proto])

    if packet_seen % 10 == 0:
        print_summary()


def print_summary():
    print("\n====== Traffic Overview ======")
    for p, c in proto_stats.items():
        print(f"{p:<6} : {c}")
    print("==============================\n")


print("\n[+] Network Traffic Analyzer Started")
print("[+] Press CTRL+C to stop\n")

try:
    sniff(prn=handle_packet, store=False)
except KeyboardInterrupt:
    print("\n[+] Capture Stopped")
    print_summary()
    log_file.close()

