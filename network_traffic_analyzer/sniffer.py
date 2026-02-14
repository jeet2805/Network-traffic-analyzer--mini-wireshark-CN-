# from scapy.all import sniff, IP, TCP, UDP, ICMP
# from collections import defaultdict
# import csv
# from datetime import datetime

# # Packet counters
# protocol_count = defaultdict(int)
# ip_count = defaultdict(int)

# # CSV file setup
# csv_file = open("logs.csv", "w", newline="")
# csv_writer = csv.writer(csv_file)
# csv_writer.writerow(["Time", "Source IP", "Destination IP", "Protocol"])

# def get_protocol(pkt):
#     if pkt.haslayer(TCP):
#         return "TCP"
#     elif pkt.haslayer(UDP):
#         return "UDP"
#     elif pkt.haslayer(ICMP):
#         return "ICMP"
#     else:
#         return "OTHER"

# packet_counter = 0

# def process_packet(packet):
#     global packet_counter
#     if packet.haslayer(IP):
#         src = packet[IP].src
#         dst = packet[IP].dst
#         proto = get_protocol(packet)

#         protocol_count[proto] += 1
#         ip_count[src] += 1

#         packet_counter += 1

#         # Print only every 3rd packet (slows output)
#         if packet_counter % 3 == 0:
#             print(f"{src:<16} → {dst:<16} | {proto}")

#         time_now = datetime.now().strftime("%H:%M:%S")
#         csv_writer.writerow([time_now, src, dst, proto])

#         if packet_counter % 10 == 0:
#             show_summary()

# def show_summary():
#     print("\n------ About Traffic------")
#     for proto, count in protocol_count.items():
#         print(f"{proto:<6} : {count}")
#     print("------------------------------\n")

# print("\n[+]Started...")
# print("[+] Press CTRL + C to stop\n")

# try:
#     sniff(prn=process_packet, store=False)
# except KeyboardInterrupt:
#     print("\n[+] Stopped.")
#     show_summary()
#     csv_file.close()
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
