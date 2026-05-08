"""
Deauthentication Attack Simulator
Generates a burst of fake deauthentication management frames targeting a
specific client MAC from a spoofed access point MAC address.
"""

import random
import string


def _random_mac() -> str:
    """Generate a random MAC address."""
    return ":".join(
        "".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(6)
    )


def simulate_deauth(
    count: int = 20,
    src_mac: str = None,
    dst_mac: str = "FF:FF:FF:FF:FF:FF",
    bssid: str = None,
    ssid: str = "VictimNet",
) -> list:
    """
    Simulate a deauthentication flood attack.

    Args:
        count:   Number of deauth frames to generate
        src_mac: Attacker's spoofed MAC (random if not provided)
        dst_mac: Target MAC address (broadcast by default)
        bssid:   BSSID of the fake / spoofed AP (random if not provided)
        ssid:    SSID of the targeted network

    Returns:
        List of packet dictionaries representing the attack traffic
    """
    src_mac = src_mac or _random_mac()
    bssid = bssid or _random_mac()

    packets = []
    for _ in range(count):
        packets.append({
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "bssid": bssid,
            "ssid": ssid,
            "frame_type": "management",
            "subtype": "deauth",
            "rssi": random.uniform(-85, -60),
            "label": "deauth_attack",
        })
    return packets
