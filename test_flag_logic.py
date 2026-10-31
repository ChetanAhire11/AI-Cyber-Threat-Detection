from scapy.all import IP, TCP
from types import SimpleNamespace

from cicflowmeter.features.flag_count import FlagCount
from cicflowmeter.features.context import PacketDirection

# Create two test packets
cwr_packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
    sport=5000, dport=80, flags="C"
)

urg_packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
    sport=5000, dport=80, flags="U"
)

# Create a test flow
flow = SimpleNamespace(
    packets=[
        (cwr_packet, PacketDirection.FORWARD),
        (urg_packet, PacketDirection.FORWARD)
    ]
)

flag_counter = FlagCount(flow)

print("CWR Count:", flag_counter.count("CWR"))
print("URG Count:", flag_counter.count("URG"))