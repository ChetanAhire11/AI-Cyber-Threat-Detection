from scapy.all import IP, TCP, Raw
from types import SimpleNamespace

from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.features.context import PacketDirection

packets = []

for size in [10, 20, 30]:
    packet = IP() / TCP() / Raw(load=b"A" * size)
    packets.append((packet, PacketDirection.FORWARD))

flow = SimpleNamespace(packets=packets)

feature = PacketLength(flow)

print("Packet Lengths:", feature.get_packet_length())
print("Variance:", feature.get_var())
print("Standard Deviation:", feature.get_std())