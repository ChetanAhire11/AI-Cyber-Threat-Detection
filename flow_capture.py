
from scapy.all import sniff, IP, TCP, UDP
import statistics

flows = {}

WIFI_INTERFACE = r"\Device\NPF_{E155F79D-EBB1-45B4-A254-33ECB0E39E05}"


def packet_callback(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        protocol = "TCP"

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        protocol = "UDP"

    else:
        return

    forward_key = (
        source_ip, destination_ip,
        source_port, destination_port, protocol
    )

    backward_key = (
        destination_ip, source_ip,
        destination_port, source_port, protocol
    )

    if forward_key in flows:
        flow_key = forward_key
        direction = "Forward"

    elif backward_key in flows:
        flow_key = backward_key
        direction = "Backward"

    else:
        flow_key = forward_key
        current_time = float(packet.time)

        flows[flow_key] = {
            "Forward_Packets": 0,
            "Backward_Packets": 0,
            "Forward_Bytes": 0,
            "Backward_Bytes": 0,

            "Start_Time": current_time,
            "Last_Time": current_time,

            "Packet_Lengths": [],
            "Flow_IATs": [],

            "Forward_Times": [],
            "Backward_Times": [],

            "Fwd_IATs": [],
            "Bwd_IATs": []
        }

        direction = "Forward"

    current_time = float(packet.time)
    packet_size = len(packet)

    # Flow IAT
    previous_time = flows[flow_key]["Last_Time"]
    iat = current_time - previous_time

    if iat > 0:
        flows[flow_key]["Flow_IATs"].append(iat)

    # Forward and Backward IAT
    if direction == "Forward":

        times = flows[flow_key]["Forward_Times"]

        if times:
            fwd_iat = current_time - times[-1]

            if fwd_iat > 0:
                flows[flow_key]["Fwd_IATs"].append(fwd_iat)

        times.append(current_time)

        flows[flow_key]["Forward_Packets"] += 1
        flows[flow_key]["Forward_Bytes"] += packet_size

    else:

        times = flows[flow_key]["Backward_Times"]

        if times:
            bwd_iat = current_time - times[-1]

            if bwd_iat > 0:
                flows[flow_key]["Bwd_IATs"].append(bwd_iat)

        times.append(current_time)

        flows[flow_key]["Backward_Packets"] += 1
        flows[flow_key]["Backward_Bytes"] += packet_size

    flows[flow_key]["Packet_Lengths"].append(packet_size)
    flows[flow_key]["Last_Time"] = current_time

    duration = (
        flows[flow_key]["Last_Time"]
        - flows[flow_key]["Start_Time"]
    )

    print("\n--------------------------------")
    print("Flow:", flow_key)
    print("Direction:", direction)
    print("Forward Packets:", flows[flow_key]["Forward_Packets"])
    print("Backward Packets:", flows[flow_key]["Backward_Packets"])
    print("Flow Duration:", round(duration, 6), "seconds")


print("Starting Network Flow Capture...")

sniff(
    iface=WIFI_INTERFACE,
    filter="ip",
    prn=packet_callback,
    count=30,
    store=False
)


print("\n========== FINAL FLOW SUMMARY ==========")

for flow, details in flows.items():

    duration = details["Last_Time"] - details["Start_Time"]

    total_bytes = (
        details["Forward_Bytes"] +
        details["Backward_Bytes"]
    )

    total_packets = (
        details["Forward_Packets"] +
        details["Backward_Packets"]
    )

    if duration > 0:
        flow_bytes_per_second = total_bytes / duration
        flow_packets_per_second = total_packets / duration
    else:
        flow_bytes_per_second = 0
        flow_packets_per_second = 0

    lengths = details["Packet_Lengths"]

    # Flow IAT
    iats = [x * 1_000_000 for x in details["Flow_IATs"]]

    # Forward IAT
    fwd_iats = [x * 1_000_000 for x in details["Fwd_IATs"]]

    # Backward IAT
    bwd_iats = [x * 1_000_000 for x in details["Bwd_IATs"]]

    print("\n--------------------------------")
    print("Flow:", flow)

    print("Forward Packets:", details["Forward_Packets"])
    print("Backward Packets:", details["Backward_Packets"])

    print("Flow Duration:", round(duration, 6), "seconds")
    print("Flow Duration:", round(duration * 1_000_000, 2), "microseconds")

    print("Total Fwd Packet Length:", details["Forward_Bytes"], "Bytes")
    print("Total Bwd Packet Length:", details["Backward_Bytes"], "Bytes")

    print("Flow Bytes/s:", round(flow_bytes_per_second, 2))
    print("Flow Packets/s:", round(flow_packets_per_second, 2))

    # Packet Length Statistics
    print("\n--- Packet Length Statistics ---")

    print("Packet Length Min:", min(lengths))
    print("Packet Length Max:", max(lengths))
    print("Packet Length Mean:", round(statistics.mean(lengths), 2))

    packet_std = statistics.stdev(lengths) if len(lengths) > 1 else 0

    print("Packet Length Std:", round(packet_std, 2))

    # Flow IAT Statistics
    print("\n--- Flow IAT Statistics ---")

    if iats:
        print("Flow IAT Mean:", round(statistics.mean(iats), 2))
        print("Flow IAT Max:", round(max(iats), 2))
        print("Flow IAT Min:", round(min(iats), 2))

        iat_std = statistics.stdev(iats) if len(iats) > 1 else 0

        print("Flow IAT Std:", round(iat_std, 2))
    else:
        print("Flow IAT Mean: 0")
        print("Flow IAT Max: 0")
        print("Flow IAT Min: 0")
        print("Flow IAT Std: 0")

    # Forward IAT Statistics
    print("\n--- Forward IAT Statistics ---")

    print("Fwd IAT Total:", round(sum(fwd_iats), 2))
    print("Fwd IAT Mean:",
          round(statistics.mean(fwd_iats), 2) if fwd_iats else 0)

    # Backward IAT Statistics
    print("\n--- Backward IAT Statistics ---")

    print("Bwd IAT Total:", round(sum(bwd_iats), 2))
    print("Bwd IAT Mean:",
          round(statistics.mean(bwd_iats), 2) if bwd_iats else 0)


print("\nTotal Unique Bidirectional Flows:", len(flows))
