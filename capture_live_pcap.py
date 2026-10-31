from scapy.all import sniff, wrpcap

WIFI_INTERFACE = r"\Device\NPF_{E155F79D-EBB1-45B4-A254-33ECB0E39E05}"

print("Capturing Wi-Fi traffic for 60 seconds...")

packets = sniff(
    iface=WIFI_INTERFACE,
    filter="ip and (tcp or udp)",
    timeout=60,
    store=True
)

print("Captured Packets:", len(packets))

if packets:
    wrpcap("live_capture.pcap", packets)
    print("PCAP saved successfully!")
else:
    print("No packets captured.")