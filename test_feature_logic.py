from scapy.all import Ether, IP, TCP, UDP, Raw
from types import SimpleNamespace

from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.context import PacketDirection

# Create test TCP packet: 10 bytes payload
tcp_packet = (
    Ether() / IP() / TCP() / Raw(load=b"A" * 10)
)

# Create test UDP packet: 7 bytes payload
udp_packet = (
    Ether() / IP() / UDP() / Raw(load=b"B" * 7)
)

# Create test flow
flow = SimpleNamespace(
    packets=[
        (tcp_packet, PacketDirection.FORWARD),
        (udp_packet, PacketDirection.REVERSE)
    ]
)

packet_length = PacketLength(flow)
flow_bytes = FlowBytes(flow)

print("TCP Payload Length:",
      packet_length.get_packet_length(PacketDirection.FORWARD))

print("UDP Payload Length:",
      packet_length.get_packet_length(PacketDirection.REVERSE))

print("TCP Header Length:",
      flow_bytes._header_size(tcp_packet))

print("UDP Header Length:",
      flow_bytes._header_size(udp_packet))