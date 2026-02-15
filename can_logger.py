"""
CAN bus logger for the ETS WiFi sniffer.

Connects to the ESP32's web API, polls for new CAN messages, and writes
them to a timestamped CSV file locally. Runs until Ctrl+C.

Usage:
    python can_logger.py [ESP32_IP]

    ESP32_IP defaults to 192.168.0.200 (static IP on local network).
    Override if needed:
        python can_logger.py 192.168.0.42

    Use helm action buttons on the web UI to annotate the log.
    Press Ctrl+C to stop -- CSV file is saved automatically.

The script deduplicates using sequence numbers from the ESP32, so no
messages are lost or doubled even with frequent polling.
"""

import csv
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen
import json

ESP32_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.200"
POLL_INTERVAL = 0.2  # seconds between polls
LOG_URL = f"http://{ESP32_IP}/log"
STATUS_URL = f"http://{ESP32_IP}/status"


def fetch_json(url: str, timeout: float = 2.0) -> list | dict | None:
    """Fetch JSON from the ESP32 web API."""
    try:
        with urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, OSError, json.JSONDecodeError) as e:
        print(f"  Connection error: {e}")
        return None


def format_mark_line(entry: dict) -> str:
    """Format a mark entry for terminal display."""
    return f"\033[1;33m  {entry['t']:>10}ms  >>> {entry['mark']}\033[0m"


def format_can_line(entry: dict) -> str:
    """Format a CAN message entry for terminal display."""
    can_id = f"0x{entry['id']:03X}"
    return f"  {entry['t']:>10}ms  {can_id}  DLC={entry['dlc']}  {entry['data']}"


def main() -> None:
    # Generate output filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = Path(f"ets_can_log_{timestamp}.csv")

    print("ETS CAN Bus Logger")
    print("==================")
    print(f"ESP32 address: {ESP32_IP}")
    print(f"Output file:   {output_file}")
    print()

    # Wait for connection to the ESP32
    print("Connecting to ESP32...", end="", flush=True)
    while True:
        status = fetch_json(STATUS_URL)
        if status is not None:
            print(f" connected! Baud: {status['baud']}")
            break
        print(".", end="", flush=True)
        time.sleep(1)

    print(f"Logging to {output_file} -- press Ctrl+C to stop\n")

    last_seq = 0
    msg_count = 0
    mark_count = 0

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "id", "extended", "rtr", "dlc", "data"])

        try:
            while True:
                entries = fetch_json(LOG_URL)
                if entries is None:
                    time.sleep(1)
                    continue

                new_entries = [e for e in entries if e.get("s", 0) > last_seq]

                for entry in new_entries:
                    seq = entry["s"]
                    ts = entry["t"]

                    if "mark" in entry:
                        writer.writerow([ts, "MARK", 0, 0, 0, entry["mark"]])
                        print(format_mark_line(entry))
                        mark_count += 1
                    else:
                        can_id = f"0x{entry['id']:X}"
                        writer.writerow([
                            ts, can_id, 0, 0, entry["dlc"], entry["data"]
                        ])
                        msg_count += 1

                    last_seq = max(last_seq, seq)

                # Flush after each batch so data is saved even on crash
                if new_entries:
                    f.flush()

                # Print a compact status line periodically
                if msg_count > 0 and msg_count % 500 == 0:
                    print(
                        f"  ... {msg_count} messages, {mark_count} marks "
                        f"logged (seq={last_seq})"
                    )

                time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            pass

    print(f"\n\nDone. {msg_count} messages and {mark_count} marks saved to {output_file}")


if __name__ == "__main__":
    main()
