"""
Evil Twin Attack Simulator
Simulates an Evil Twin scenario where a rogue AP clones the SSID of a
legitimate network but uses a different BSSID and often a stronger signal.
"""

import random


def _random_mac() -> str:
    return ":".join(
        "".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(6)
    )


def simulate_evil_twin(
    count: int = 10,
    legitimate_bssid: str = "AA:BB:CC:DD:EE:00",
    evil_bssid: str = None,
    ssid: str = "HomeNet",
) -> list:
    """
    Simulate an Evil Twin attack: a rogue AP broadcasting the same SSID as
    a legitimate network but using a different BSSID.

    Args:
        count:            Number of beacon frames from the evil twin to generate
        legitimate_bssid: MAC of the real AP (used as context / comparison)
        evil_bssid:       MAC of the evil AP (random if not provided)
        ssid:             SSID that the evil AP clones

    Returns:
        List of packet dictionaries representing evil twin beacon traffic
    """
    evil_bssid = evil_bssid or _random_mac()

    packets = []
    for _ in range(count):
        packets.append({
            "src_mac": evil_bssid,
            "dst_mac": "FF:FF:FF:FF:FF:FF",
            "bssid": evil_bssid,
            "ssid": ssid,
            "frame_type": "management",
            "subtype": "beacon",
            "rssi": random.uniform(-60, -40),  # Stronger signal to lure victims
            "label": "evil_twin",
        })
    return packets
