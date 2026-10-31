from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from cicflowmeter.flow import Flow
from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.context import PacketDirection


def create_packet(timestamp):
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=5000, dport=80, flags="PA")
        / Raw(load=b"A" * 100)
    )

    packet.time = timestamp
    return packet


# Create flow with first packet
flow = Flow(
    create_packet(100.0),
    PacketDirection.FORWARD
)

# Add three more packets
for timestamp in [100.1, 100.2, 100.3]:
    flow.add_packet(
        create_packet(timestamp),
        PacketDirection.FORWARD
    )

flow_bytes = FlowBytes(flow)

print("Total Packets:", len(flow.packets))
print("Bulk Count:", flow.forward_bulk_count)
print("Bulk Packets:", flow.forward_bulk_packet_count)
print("Bulk Bytes:", flow.forward_bulk_size)
print("Bulk Duration:", flow.forward_bulk_duration)
print("Average Bytes per Bulk:",
      flow_bytes.get_bytes_per_bulk(PacketDirection.FORWARD))