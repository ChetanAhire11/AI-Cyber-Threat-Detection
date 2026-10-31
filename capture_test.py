from scapy.all import sniff, wrpcap

WIFI_INTERFACE = r"\Device\NPF_{E155F79D-EBB1-45B4-A254-33ECB0E39E05}"

print("Capturing packets...")

packets = sniff(
    iface=WIFI_INTERFACE,
    filter="ip",
    count=100,
    store=True
)

print("Captured Packets:", len(packets))

wrpcap("test_traffic.pcap", packets)

print("PCAP File Created Successfully!")