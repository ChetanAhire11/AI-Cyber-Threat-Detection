"""Near-real-time packet capture worker for CyberGuard.

Captures short, authorized Wi-Fi traffic windows, converts each PCAP window
with the separate CICFlowMeter environment, and atomically updates live_flows.csv.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
from scapy.all import sniff, wrpcap

BASE_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = BASE_DIR / "runtime"
RUNTIME_DIR.mkdir(exist_ok=True)

WIFI_INTERFACE = r"\Device\NPF_{E155F79D-EBB1-45B4-A254-33ECB0E39E05}"
CAPTURE_SECONDS = 10

PCAP_FILE = RUNTIME_DIR / "capture_window.pcap"
TEMP_CSV = RUNTIME_DIR / "window_flows.csv"
LIVE_CSV = BASE_DIR / "live_flows.csv"
STOP_FLAG = RUNTIME_DIR / "stop_capture.flag"
STATUS_FILE = RUNTIME_DIR / "capture_status.json"
CICFLOWMETER_EXE = BASE_DIR / "cicflowmeter_env" / "Scripts" / "cicflowmeter.exe"


def write_status(**updates: object) -> None:
    current: dict[str, object] = {}
    if STATUS_FILE.exists():
        try:
            current = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = {}
    current.update(updates)
    current["updated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    temp_status = STATUS_FILE.with_suffix(".tmp")
    temp_status.write_text(json.dumps(current, indent=2), encoding="utf-8")
    os.replace(temp_status, STATUS_FILE)


def append_csv_atomically(batch_csv: Path) -> int:
    batch = pd.read_csv(batch_csv)
    if batch.empty:
        return 0

    if LIVE_CSV.exists() and LIVE_CSV.stat().st_size > 0:
        existing = pd.read_csv(LIVE_CSV)
        # Guard against unexpected schema changes between batches.
        if list(existing.columns) != list(batch.columns):
            raise ValueError("CICFlowMeter columns changed between capture windows.")
        combined = pd.concat([existing, batch], ignore_index=True)
    else:
        combined = batch

    temp_live = LIVE_CSV.with_suffix(".next.csv")
    combined.to_csv(temp_live, index=False)
    os.replace(temp_live, LIVE_CSV)
    return len(batch)


def main() -> int:
    if not CICFLOWMETER_EXE.exists():
        write_status(state="error", message=f"CICFlowMeter not found: {CICFLOWMETER_EXE}")
        return 1

    write_status(
        state="running",
        message="Capture worker started.",
        pid=os.getpid(),
        capture_seconds=CAPTURE_SECONDS,
        last_packets=0,
        last_flows=0,
    )

    try:
        while not STOP_FLAG.exists():
            write_status(state="running", message=f"Capturing Wi-Fi traffic for {CAPTURE_SECONDS} seconds...")

            packets = sniff(
                iface=WIFI_INTERFACE,
                filter="ip and (tcp or udp)",
                timeout=CAPTURE_SECONDS,
                store=True,
            )

            # If Stop was requested during this window, finish processing
            # the captured packets, then exit at the next loop check.
            if not packets:
                write_status(
                    state="running",
                    message="No TCP/UDP packets in the latest window. Continuing capture.",
                    last_packets=0,
                    last_flows=0,
                )
                continue

            wrpcap(str(PCAP_FILE), packets)
            if TEMP_CSV.exists():
                TEMP_CSV.unlink()

            write_status(
                state="running",
                message=f"Captured {len(packets)} packets. Extracting flow features...",
                last_packets=len(packets),
            )

            completed = subprocess.run(
                [
                    str(CICFLOWMETER_EXE),
                    "-f", str(PCAP_FILE),
                    "-c", str(TEMP_CSV),
                ],
                cwd=str(BASE_DIR),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )

            if completed.returncode != 0:
                error_text = (completed.stderr or completed.stdout or "Unknown CICFlowMeter error").strip()
                write_status(
                    state="running",
                    message=f"CICFlowMeter error: {error_text[-1200:]}",
                    last_flows=0,
                )
                continue

            if not TEMP_CSV.exists() or TEMP_CSV.stat().st_size == 0:
                write_status(
                    state="running",
                    message=f"Captured {len(packets)} packets; no complete flows in this window yet.",
                    last_packets=len(packets),
                    last_flows=0,
                )
                continue

            try:
                new_flows = append_csv_atomically(TEMP_CSV)
            except Exception as exc:  # Keep the capture worker alive on a bad batch.
                write_status(state="running", message=f"Could not append flow batch: {exc}", last_flows=0)
                continue

            total_flows = 0
            if LIVE_CSV.exists() and LIVE_CSV.stat().st_size > 0:
                try:
                    total_flows = sum(1 for _ in LIVE_CSV.open("r", encoding="utf-8")) - 1
                except OSError:
                    total_flows = 0

            write_status(
                state="running",
                message=f"Latest window: {new_flows} flows added.",
                last_packets=len(packets),
                last_flows=new_flows,
                total_flows=max(total_flows, 0),
                last_batch_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            )

    except KeyboardInterrupt:
        write_status(state="stopping", message="Stop requested; finishing current capture window.")
    except Exception as exc:
        write_status(state="error", message=f"Capture worker stopped: {type(exc).__name__}: {exc}")
        return 1
    finally:
        write_status(state="stopped", message="Capture stopped.")
        for path in (PCAP_FILE, TEMP_CSV):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
