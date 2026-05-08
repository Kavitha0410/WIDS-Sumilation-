"""
Logging System Module
Saves threat detection events to a CSV file with timestamps, attack types,
severity levels, and details. Uses an in-memory list as a buffer.

Each fresh run of main.py truncates the previous log and starts clean.
"""

import csv
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "threat_logs.csv")

_LOG_FIELDNAMES = ["timestamp", "attack_type", "severity", "details"]

# In-memory log buffer for this session
_log_buffer: list[dict] = []

# Tracks whether the CSV has been initialised (truncated) this session
_session_started: bool = False


def _ensure_log_file():
    """
    At the very first log_threat() call in this process, truncate the CSV and
    write fresh headers.  All subsequent calls simply append rows.
    """
    global _session_started
    os.makedirs(LOG_DIR, exist_ok=True)
    if not _session_started:
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_LOG_FIELDNAMES)
            writer.writeheader()
        _session_started = True


def log_threat(attack_type: str, severity: str, details: str):
    """
    Log a detected threat to both the in-memory buffer and the CSV file.

    Args:
        attack_type: Type of attack detected (e.g., 'Deauthentication Attack')
        severity: Severity level ('High', 'Medium', 'Low')
        details: Human-readable description of the event
    """
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack_type": attack_type,
        "severity": severity,
        "details": details,
    }
    _log_buffer.append(entry)
    _ensure_log_file()
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_LOG_FIELDNAMES)
        writer.writerow(entry)


def get_logs() -> list:
    """Return all log entries recorded this session."""
    return list(_log_buffer)


def clear_logs():
    """Clear the in-memory log buffer (does not touch the CSV file)."""
    _log_buffer.clear()
