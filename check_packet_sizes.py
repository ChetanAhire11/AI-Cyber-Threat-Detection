from scapy.all import PcapReader, Ether, IP, TCP, UDP

count = 0

with PcapReader("test_traffic.pcap") as packets:

    for packet in packets:

        if IP not in packet:
            continue

        ip_packet = packet[IP]

        print("\n-------------------------------")
        print("Packet:", count + 1)

        # Complete captured frame
        print("Full Packet Length:", len(packet))

        # IP packet length without Ethernet
        print("IP Packet Length:", len(ip_packet))

        # IP header length
        print("IP Header Length:", ip_packet.ihl * 4)

        if TCP in packet:
            print("TCP Header Length:", packet[TCP].dataofs * 4)
            print("TCP Payload Length:", len(packet[TCP].payload))

        elif UDP in packet:
            print("UDP Header Length: 8")
            print("UDP Payload Length:", len(packet[UDP].payload))

        count += 1

        if count == 5:
            break
