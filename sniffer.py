from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import os

CSV_FILE = "packet_log.csv"


def create_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as file:
            writer = csv.writer(file)

            writer.writerow([
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Source Port",
                "Destination Port",
                "Packet Length",
                "Payload Length"
            ])


def packet_callback(packet):

    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

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

    elif ICMP in packet:
        protocol = "ICMP"

    else:
        protocol = "Other"

    packet_length = len(packet)

    # Get payload information without displaying its contents
    if packet.payload:
        payload_length = len(bytes(packet.payload))
    else:
        payload_length = 0

    print(
        f"{timestamp} | "
        f"{source_ip} -> {destination_ip} | "
        f"{protocol} | "
        f"{source_port} -> {destination_port} | "
        f"Packet: {packet_length} bytes | "
        f"Payload: {payload_length} bytes"
    )

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
            payload_length
        ])


create_csv()

print("=" * 80)
print("                 NETWORK PACKET SNIFFER")
print("=" * 80)
print("Capturing traffic from your authorized lab system...")
print("Press CTRL+C to stop.")
print()

sniff(
    iface="eth0",
    filter="ip",
    prn=packet_callback,
    store=False
)
