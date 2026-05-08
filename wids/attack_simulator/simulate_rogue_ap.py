"""
Rogue AP Attack Simulator
Generates beacon frames from an unauthorized access point broadcasting on the
network — designed to lure clients away from legitimate APs.
"""

import random


def _random_mac() -> str:
    return ":".join(
        "".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(6)
    )


def simulate_rogue_ap(
    count: int = 10,
    bssid: str = None,
    ssid: str = "FreePublicWiFi",
) -> list:
    """
    Simulate a Rogue AP broadcasting beacon frames.

    Args:
        count:  Number of beacon frames to generate
        bssid:  BSSID of the rogue AP (random if not provided)
        ssid:   SSID the rogue AP broadcasts

    Returns:
        List of packet dictionaries representing beacon traffic from a rogue AP
    """
    bssid = bssid or _random_mac()

    packets = []
    for _ in range(count):
        packets.append({
            "src_mac": bssid,
            "dst_mac": "FF:FF:FF:FF:FF:FF",
            "bssid": bssid,
            "ssid": ssid,
            "frame_type": "management",
            "subtype": "beacon",
            "rssi": random.uniform(-75, -50),
            "label": "rogue_ap",
        })
    return packets
