from scapy.all import PcapReader, TCP

cwr_count = 0
urg_count = 0
tcp_count = 0

with PcapReader("test_traffic.pcap") as packets:
    for packet in packets:

        if packet.haslayer(TCP):
            tcp_count += 1

            flags = int(packet[TCP].flags)

            if flags & 0x80:
                cwr_count += 1

            if flags & 0x20:
                urg_count += 1

print("Total TCP Packets:", tcp_count)
print("Actual CWR Flags:", cwr_count)
print("Actual URG Flags:", urg_count)