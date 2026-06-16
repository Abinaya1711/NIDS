"""
suricata_monitor.py — Suricata eve.json Log Monitor for AI-NIDS
Monitors the Suricata eve.json log file in real time, parses alert events,
and inserts them into the SQLite database.
"""

import json
import os
import time
import threading
from database import insert_alert

# Default path — Suricata typically writes to /var/log/suricata/eve.json on Linux
DEFAULT_EVE_PATH = '/var/log/suricata/eve.json'


class SuricataMonitor:
    """Monitors Suricata's eve.json log file and processes alert events."""

    def __init__(self, eve_path=None):
        self.eve_path = eve_path or DEFAULT_EVE_PATH
        self.running = False
        self._thread = None
        self._file_position = 0
        self._processed_count = 0

    def parse_eve_line(self, line):
        """
        Parse a single JSON line from eve.json.
        Returns a dict with alert fields if it's an alert event, else None.
        """
        try:
            data = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            return None

        # Only process alert events
        if data.get('event_type') != 'alert':
            return None

        alert_info = data.get('alert', {})

        parsed = {
            'timestamp': data.get('timestamp', ''),
            'src_ip': data.get('src_ip', 'unknown'),
            'dest_ip': data.get('dest_ip', 'unknown'),
            'src_port': data.get('src_port', 0),
            'dest_port': data.get('dest_port', 0),
            'protocol': data.get('proto', 'unknown'),
            'signature': alert_info.get('signature', 'Unknown Signature'),
            'signature_id': alert_info.get('signature_id', 0),
            'severity': alert_info.get('severity', 3),
            'category': alert_info.get('category', 'Uncategorized'),
            'raw_json': line.strip()
        }

        return parsed

    def _process_new_lines(self):
        """Read and process new lines from eve.json since last position."""
        try:
            if not os.path.exists(self.eve_path):
                return 0

            file_size = os.path.getsize(self.eve_path)

            # If file was truncated/rotated, reset position
            if file_size < self._file_position:
                self._file_position = 0

            if file_size == self._file_position:
                return 0

            count = 0
            with open(self.eve_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self._file_position)
                for line in f:
                    if not line.strip():
                        continue
                    parsed = self.parse_eve_line(line)
                    if parsed:
                        try:
                            insert_alert(
                                timestamp=parsed['timestamp'],
                                src_ip=parsed['src_ip'],
                                dest_ip=parsed['dest_ip'],
                                src_port=parsed['src_port'],
                                dest_port=parsed['dest_port'],
                                protocol=parsed['protocol'],
                                signature=parsed['signature'],
                                signature_id=parsed['signature_id'],
                                severity=parsed['severity'],
                                category=parsed['category'],
                                raw_json=parsed['raw_json']
                            )
                            count += 1
                        except Exception as e:
                            print(f"[MONITOR] Error inserting alert: {e}")

                self._file_position = f.tell()

            if count > 0:
                self._processed_count += count
                print(f"[MONITOR] Processed {count} new alerts. Total: {self._processed_count}")

            return count

        except Exception as e:
            print(f"[MONITOR] Error reading eve.json: {e}")
            return 0

    def monitor(self, poll_interval=2):
        """
        Continuously monitor the eve.json file for new alert entries.
        Polls the file at the specified interval (seconds).
        """
        print(f"[MONITOR] Starting Suricata monitor on: {self.eve_path}")
        print(f"[MONITOR] Poll interval: {poll_interval}s")

        if not os.path.exists(self.eve_path):
            print(f"[MONITOR] Warning: {self.eve_path} not found. Will retry when file appears.")

        self.running = True
        while self.running:
            self._process_new_lines()
            time.sleep(poll_interval)

        print("[MONITOR] Suricata monitor stopped.")

    def start(self, poll_interval=2):
        """Start monitoring in a background daemon thread."""
        if self._thread and self._thread.is_alive():
            print("[MONITOR] Monitor already running.")
            return

        self._thread = threading.Thread(
            target=self.monitor,
            args=(poll_interval,),
            daemon=True,
            name="SuricataMonitor"
        )
        self._thread.start()
        print("[MONITOR] Background monitor thread started.")

    def stop(self):
        """Stop the monitor."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[MONITOR] Monitor stopped.")

    def get_status(self):
        """Get the current monitor status."""
        return {
            'running': self.running,
            'eve_path': self.eve_path,
            'file_exists': os.path.exists(self.eve_path),
            'processed_count': self._processed_count,
            'file_position': self._file_position
        }


def process_existing_log(eve_path=None):
    """
    One-shot processing of an existing eve.json file.
    Useful for importing historical logs.
    """
    monitor = SuricataMonitor(eve_path)
    count = monitor._process_new_lines()
    print(f"[IMPORT] Imported {count} alerts from {monitor.eve_path}")
    return count
