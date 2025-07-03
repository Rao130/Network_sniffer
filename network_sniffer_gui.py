import customtkinter as ctk
import threading
import pandas as pd
import matplotlib.pyplot as plt
import requests
import socket
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

# Initialize GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Advanced Network Packet Sniffer")
app.geometry("1000x500")

# Packet storage
packet_list = []
ip_counter = Counter()
port_counter = Counter()
sniffing = False  # Control flag for sniffing

# Function to get hostname of an IP
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown System"

# Function to check if an IP is blacklisted
def is_malicious(ip):
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check",
                                params={"ipAddress": ip},
                                headers={"Key": "YOUR_API_KEY"})
        data = response.json()
        return data["data"]["abuseConfidenceScore"] > 50
    except:
        return False

# Function to analyze packets
def analyze_packet(packet):
    if not sniffing:  # Stop capturing if the flag is False
        return

    alert = ""
    source_ip = packet[IP].src if IP in packet else "Unknown"
    destination_ip = packet[IP].dst if IP in packet else "Unknown"
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
    length = len(packet)
    hostname = get_hostname(source_ip)

    # Attack detection
    ip_counter[source_ip] += 1
    if ip_counter[source_ip] > 100:
        alert = "⚠️ Possible DDoS Attack!"
    if TCP in packet:
        port = packet[TCP].dport
        port_counter[(source_ip, port)] += 1
        if port_counter[(source_ip, port)] > 10:
            alert = "⚠️ Port Scanning Detected!"

    if is_malicious(source_ip):
        alert = "🚨 Blacklisted IP!"

    # TCP Packet details
    if TCP in packet:
        tcp_info = f"SRC Port: {packet[TCP].sport}, DST Port: {packet[TCP].dport}, Flags: {packet[TCP].flags}, Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack}"
    else:
        tcp_info = "N/A"

    # UDP Packet details
    if UDP in packet:
        udp_info = f"UDP SRC Port: {packet[UDP].sport}, DST Port: {packet[UDP].dport}, Length: {packet[UDP].len}"
    else:
        udp_info = "N/A"

    # ICMP Packet details
    if ICMP in packet:
        icmp_info = f"ICMP Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
    else:
        icmp_info = "N/A"

    # Add to list & update GUI
    packet_list.append([source_ip, hostname, destination_ip, protocol, length, alert, tcp_info, udp_info, icmp_info])
    tree.insert("", "end", values=(source_ip, hostname, destination_ip, protocol, length, alert, tcp_info, udp_info, icmp_info), tags=("alert" if alert else ""))

# Function to start sniffing
def start_sniffing():
    global sniffing
    sniffing = True
    sniff(prn=analyze_packet, store=False)

# Function to stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False

# Run sniffing in a separate thread
def start_sniffing_thread():
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()

# Function to visualize packet data
def visualize_data():
    df = pd.DataFrame(packet_list, columns=["Source IP", "System", "Destination IP", "Protocol", "Length", "Alert", "TCP Info", "UDP Info", "ICMP Info"])
    protocol_counts = df["Protocol"].value_counts()

    plt.figure(figsize=(8, 5))
    protocol_counts.plot(kind="bar", color="blue", edgecolor="black")
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.show()

# GUI Layout
frame = ctk.CTkFrame(app)
frame.pack(fill="both", expand=True, padx=10, pady=10)

columns = ["Source IP", "System", "Destination IP", "Protocol", "Length", "Alert", "TCP Info", "UDP Info", "ICMP Info"]
tree = ttk.Treeview(frame, columns=columns, show="headings")

# Add column headings
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

tree.pack(fill="both", expand=True)

btn_frame = ctk.CTkFrame(app)
btn_frame.pack(fill="x", pady=10)

start_btn = ctk.CTkButton(btn_frame, text="Start Sniffing", command=start_sniffing_thread, fg_color="green")
start_btn.pack(side="left", padx=10)

stop_btn = ctk.CTkButton(btn_frame, text="Stop Sniffing", command=stop_sniffing, fg_color="red")
stop_btn.pack(side="left", padx=10)

visualize_btn = ctk.CTkButton(btn_frame, text="Visualize Traffic", command=visualize_data, fg_color="blue")
visualize_btn.pack(side="right", padx=10)

# Run App
app.mainloop()
