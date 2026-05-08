"""
Feature Extraction Module
Extracts and normalizes key fields from raw packet dictionaries.
These standardized fields are used by the feature fusion and detection layers.
"""


def extract_features(packet: dict) -> dict:
    """
    Extract key fields from a raw packet dictionary and return a normalized
    feature set. Unknown or missing values are filled with safe defaults.

    Args:
        packet: Raw packet dictionary (from dataset or simulator)

    Returns:
        Dictionary with cleaned, normalized feature fields
    """
    return {
        "src_mac": str(packet.get("src_mac", "00:00:00:00:00:00")).strip().upper(),
        "dst_mac": str(packet.get("dst_mac", "FF:FF:FF:FF:FF:FF")).strip().upper(),
        "bssid": str(packet.get("bssid", "00:00:00:00:00:00")).strip().upper(),
        "ssid": str(packet.get("ssid", "unknown")).strip(),
        "frame_type": str(packet.get("frame_type", "unknown")).strip().lower(),
        "subtype": str(packet.get("subtype", "unknown")).strip().lower(),
        "rssi": _safe_float(packet.get("rssi", -100)),
        "label": str(packet.get("label", "normal")).strip().lower(),
    }


def _safe_float(value, default: float = -100.0) -> float:
    """Safely convert a value to float, returning a default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
