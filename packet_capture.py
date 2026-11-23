from scapy.all import sniff, IP, TCP, UDP
import csv
import os
from datetime import datetime


CSV_FILE = "dataset/packet_data.csv"


# Create CSV file if it doesn't exist
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Source_IP",
            "Destination_IP",
            "Protocol",
            "Source_Port",
            "Destination_Port",
            "Packet_Length",
            "TTL"
        ])


def analyze_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_length = len(packet)
    ttl = packet[IP].ttl

    protocol = "Other"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save packet information
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length,
            ttl
        ])

    # Display packet information
    print("\n-----------------------------")
    print("Time            :", timestamp)
    print("Source IP       :", source_ip)
    print("Destination IP  :", destination_ip)
    print("Protocol        :", protocol)
    print("Source Port     :", source_port)
    print("Destination Port:", destination_port)
    print("Packet Length   :", packet_length)
    print("TTL             :", ttl)
    print("-----------------------------")


print("Starting Network Packet Capture...")
print("Packet data will be saved to:", CSV_FILE)
print("Press CTRL+C to stop.\n")

sniff(prn=analyze_packet, store=False)