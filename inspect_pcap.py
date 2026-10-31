from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from collections import Counter

counts = Counter()

with PcapReader("test_traffic.pcap") as packets:
    for packet in packets:
        counts["Total Packets"] += 1

        if packet.haslayer(IP):
            counts["IPv4 Packets"] += 1

        elif packet.haslayer(IPv6):
            counts["IPv6 Packets"] += 1

        else:
            counts["Non-IP Packets"] += 1

        if packet.haslayer(TCP):
            counts["TCP Packets"] += 1

        elif packet.haslayer(UDP):
            counts["UDP Packets"] += 1

        else:
            counts["Other Protocol Packets"] += 1

print("\nPacket Analysis:")
for name, count in counts.items():
    print(f"{name}: {count}")