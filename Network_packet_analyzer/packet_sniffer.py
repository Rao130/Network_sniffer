import csv
from scapy.all import sniff, IP, TCP, UDP, ICMP
import os
from collections import Counter

# Define CSV file
csv_file = "network_traffic.csv"

# Create CSV file with headers if it doesn't exist
if not os.path.exists(csv_file):
    with open(csv_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Source IP", "Destination IP", "Protocol", "Length", "Alert"])

# Counters for attack detection
ip_counter = Counter()
port_counter = Counter()

# Function to detect suspicious activity
def detect_attack(packet):
    alert = ""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"

        # Count packets from each source IP
        ip_counter[src_ip] += 1

        # Detect DoS/DDoS: If an IP sends more than 100 packets in a short time
        if ip_counter[src_ip] > 100:
            alert = "Possible DoS/DDoS Attack!"

        # Detect Port Scanning: If an IP is trying multiple ports rapidly
        if TCP in packet:
            port = packet[TCP].dport
            port_counter[(src_ip, port)] += 1
            if port_counter[(src_ip, port)] > 10:
                alert = "Port Scanning Detected!"

        # Log packet data
        packet_data = [src_ip, dst_ip, protocol, len(packet), alert]

        # Append packet data to CSV
        with open(csv_file, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(packet_data)

        # Print alert if detected
        if alert:
            print(f"⚠️ ALERT: {alert} from {src_ip}")

# Start sniffing packets
print("Starting packet sniffing... Press CTRL+C to stop.")
sniff(prn=detect_attack, store=False)
