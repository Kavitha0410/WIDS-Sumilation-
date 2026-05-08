"""
MAC Spoofing Detection Module
Detects when a device changes its MAC address or when the same MAC address
appears associated with multiple distinct BSSIDs — a common spoofing indicator.
"""

from collections import defaultdict


class MACSpoofingDetection:
    """Tracks MAC-to-BSSID associations and flags frequent changes."""

    BSSID_THRESHOLD = 3  # Distinct BSSIDs per MAC before flagging

    def __init__(self):
        # src_mac -> set of BSSIDs it has used
        self._mac_bssid_map: dict = defaultdict(set)

    def inspect(self, packet: dict) -> tuple | None:
        """
        Inspect a packet for MAC spoofing behaviour.

        Returns:
            (attack_type, severity, details) tuple if spoofing detected, else None.
        """
        src_mac = packet.get("src_mac", "").upper()
        bssid = packet.get("bssid", "").upper()

        if not src_mac:
            return None

        self._mac_bssid_map[src_mac].add(bssid)
        count = len(self._mac_bssid_map[src_mac])

        if count > self.BSSID_THRESHOLD:
            return (
                "MAC Spoofing Detected",
                "Medium",
                f"MAC {src_mac} has been observed with {count} different BSSIDs",
            )
        return None
