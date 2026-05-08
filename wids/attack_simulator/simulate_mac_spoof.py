"""
MAC Spoofing Attack Simulator
Simulates a device rapidly cycling through different MAC addresses to avoid
tracking or to impersonate other devices on the network.
"""

import random


def _random_mac() -> str:
    return ":".join(
        "".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(6)
    )


def simulate_mac_spoof(
    count: int = 15,
    target_ssid: str = "HomeNet",
    num_macs: int = 8,
) -> list:
    """
    Simulate a MAC spoofing session where one logical attacker cycles through
    multiple MAC addresses while connecting to the same SSID.

    Args:
        count:       Total number of packets to generate
        target_ssid: SSID the attacker probes
        num_macs:    Number of distinct MAC addresses the attacker rotates through

    Returns:
        List of packet dictionaries representing the spoofed traffic
    """
    mac_pool = [_random_mac() for _ in range(num_macs)]
    bssid = _random_mac()

    packets = []
    for i in range(count):
        src_mac = mac_pool[i % num_macs]
        packets.append({
            "src_mac": src_mac,
            "dst_mac": bssid,
            "bssid": bssid,
            "ssid": target_ssid,
            "frame_type": "management",
            "subtype": "probe_request",
            "rssi": random.uniform(-80, -55),
            "label": "mac_spoofing",
        })
    return packets
