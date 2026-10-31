
import subprocess
import sys
from pathlib import Path

from scapy.all import sniff, wrpcap

BASE_DIR = Path(__file__).resolve().parent

WIFI_INTERFACE = (
    r"\Device\NPF_{E155F79D-EBB1-45B4-A254-33ECB0E39E05}"
)

PCAP_FILE = BASE_DIR / "live_capture.pcap"
CSV_FILE = BASE_DIR / "live_flows.csv"

CICFLOWMETER = (
    BASE_DIR
    / "cicflowmeter_env"
    / "Scripts"
    / "cicflowmeter.exe"
)

print("\n===== AI CYBER THREAT DETECTION =====")

# Step 1: Capture packets
print("\n[1/3] Capturing Wi-Fi traffic for 60 seconds...")

packets = sniff(
    iface=WIFI_INTERFACE,
    filter="ip and (tcp or udp)",
    timeout=60,
    store=True
)

print("Captured Packets:", len(packets))

if not packets:
    print("No packets captured. Check network interface.")
    sys.exit(1)

wrpcap(str(PCAP_FILE), packets)

print("PCAP saved successfully!")


# Step 2: Extract network flows
print("\n[2/3] Extracting network flow features...")

if not CICFLOWMETER.exists():
    print("CICFlowMeter executable not found!")
    sys.exit(1)

try:
    subprocess.run(
        [
            str(CICFLOWMETER),
            "-f",
            str(PCAP_FILE),
            "-c",
            str(CSV_FILE)
        ],
        cwd=str(BASE_DIR),
        check=True
    )

except subprocess.CalledProcessError as error:
    print("CICFlowMeter failed:", error)
    sys.exit(1)

if not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0:
    print("No flow data generated!")
    sys.exit(1)

print("Flow CSV generated successfully!")


# Step 3: Dashboard update
print("\n[3/3] Pipeline completed!")

print("PCAP:", PCAP_FILE)
print("CSV:", CSV_FILE)

print("\nOpen dashboard using:")
print("streamlit run dashboard.py")
