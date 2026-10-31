from scapy.layers.inet import IP, TCP

from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection


def create_packet(timestamp):
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=5000, dport=80, flags="PA")
    )
    packet.time = timestamp
    return packet


# First packet at 0 seconds
flow = Flow(
    create_packet(0),
    PacketDirection.FORWARD
)

# Remaining packets
for timestamp in [0.5, 1.0, 2.0, 8.0]:
    flow.add_packet(
        create_packet(timestamp),
        PacketDirection.FORWARD
    )

print("Active Periods:", flow.active)
print("Idle Periods:", flow.idle)