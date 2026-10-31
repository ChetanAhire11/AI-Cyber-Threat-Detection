from scapy.all import sniff, IP, TCP, UDP

WIFI_INTERFACE = r"\Device\NPF_{E155F79D-EBB1-45B4-A254-33ECB0E39E05}"


def packet_callback(packet):

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"

        elif UDP in packet:
            protocol = "UDP"

        else:
            protocol = "Other"

        print("--------------------------------")
        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)
        print("Protocol:", protocol)


print("Starting Wi-Fi Live Capture...")

sniff(
    iface=WIFI_INTERFACE,
    filter="ip",
    prn=packet_callback,
    count=20,
    store=False
)

print("Capture Completed!")