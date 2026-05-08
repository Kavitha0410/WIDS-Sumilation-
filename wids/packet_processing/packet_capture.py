"""
Packet Capture Module
Loads training data from the WIDS threat log dataset CSV supplied by the user.
Each row is converted into a normalized packet dictionary that the existing
feature-extraction and ML pipeline can consume directly.

Dataset format expected:
    timestamp, attack_type, severity, details
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd

DATASET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "dataset", "wids_threat_logs.csv"
)

# ------------------------------------------------------------------ helpers

# Map attack_type strings → canonical label used by the ML model
_LABEL_MAP = {
    "deauthentication attack":   "deauth_attack",
    "evil twin attack":          "evil_twin",
    "rogue ap detected":         "rogue_ap",
    "mac spoofing detected":     "mac_spoofing",
    "anomalous traffic (ml)":    "anomaly",
}

_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_RATIO_RE = re.compile(r"window ratio=([0-9.]+)")
_BSSID_RE = re.compile(r"BSSID ([0-9A-Fa-f:]{17})")
_SSID_RE  = re.compile(r"SSID '([^']+)'")
_CONF_RE  = re.compile(r"confidence (\d+)%")

_SUBTYPE_BY_LABEL = {
    "deauth_attack": "deauth",
    "evil_twin":     "beacon",
    "rogue_ap":      "beacon",
    "mac_spoofing":  "probe_request",
    "anomaly":       "unknown",
    "normal":        "unknown",
}


def _infer_label(attack_type: str) -> str:
    """Derive a canonical label from the attack_type column."""
    key = attack_type.strip().lower()
    # Handle ML-detected variants like 'ML-Detected Attack (deauth_attack)'
    ml_match = re.search(r"\(([^)]+)\)", key)
    if ml_match:
        inner = ml_match.group(1).strip()
        return inner  # already canonical, e.g. 'deauth_attack', 'evil_twin'
    return _LABEL_MAP.get(key, "normal")


def _row_to_packet(row: pd.Series) -> dict:
    """Convert one CSV row → packet dict suitable for feature extraction."""
    attack_type = str(row.get("attack_type", "normal"))
    details     = str(row.get("details", ""))

    label   = _infer_label(attack_type)
    subtype = _SUBTYPE_BY_LABEL.get(label, "unknown")

    # Extract MAC from details where possible
    macs = _MAC_RE.findall(details)
    src_mac = macs[0].upper() if macs else "00:00:00:00:00:00"
    bssid   = macs[1].upper() if len(macs) > 1 else src_mac

    # Extract SSID
    ssid_m = _SSID_RE.search(details)
    ssid   = ssid_m.group(1) if ssid_m else "HomeNet"

    # Extract deauth ratio as a proxy for RSSI-like numeric signal
    ratio_m = _RATIO_RE.search(details)
    ratio   = float(ratio_m.group(1)) if ratio_m else 0.0

    # Use ratio to derive a plausible RSSI value (range -30 to -90 dBm)
    rssi = -30.0 - (ratio * 60.0)

    return {
        "src_mac":    src_mac,
        "dst_mac":    "FF:FF:FF:FF:FF:FF",
        "bssid":      bssid,
        "ssid":       ssid,
        "frame_type": "management",
        "subtype":    subtype,
        "rssi":       rssi,
        "label":      label,
    }


# ------------------------------------------------------------------ public API

def load_dataset_packets(max_packets: int = 2000) -> list:
    """
    Load packets from the user-provided wids_threat_logs.csv dataset.
    Falls back to a minimal dummy set only if the file is missing.

    Args:
        max_packets: Maximum number of rows to load (default 2000)

    Returns:
        List of packet dictionaries ready for feature extraction.
    """
    if not os.path.exists(DATASET_PATH):
        print(f"[PacketCapture] Dataset not found at '{DATASET_PATH}'.")
        print("[PacketCapture] Please place 'wids_threat_logs.csv' in the dataset/ folder.")
        return []

    print(f"[PacketCapture] Loading dataset: {DATASET_PATH}")
    try:
        df = pd.read_csv(DATASET_PATH, nrows=max_packets)
        # Drop rows with missing attack_type
        df = df.dropna(subset=["attack_type"])
        packets = [_row_to_packet(row) for _, row in df.iterrows()]
        label_counts = {}
        for p in packets:
            label_counts[p["label"]] = label_counts.get(p["label"], 0) + 1
        print(f"[PacketCapture] Loaded {len(packets)} records.")
        print(f"[PacketCapture] Label distribution: {label_counts}")
        return packets
    except Exception as exc:
        print(f"[PacketCapture] Error reading CSV: {exc}")
        return []


def load_simulated_packets(simulated: list) -> list:
    """Pass-through: normalize a list of simulated attack packet dicts."""
    from packet_processing.feature_extraction import extract_features
    return [extract_features(pkt) for pkt in simulated]
