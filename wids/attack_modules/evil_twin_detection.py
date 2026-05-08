"""
Evil Twin Detection Module
Detects Evil Twin attacks: a rogue AP that impersonates a legitimate AP by
broadcasting the same SSID but with a different BSSID.
"""

from collections import defaultdict


class EvilTwinDetection:
    """Tracks SSID-to-BSSID mappings and flags SSID collisions."""

    def __init__(self):
        # ssid -> set of BSSIDs seen broadcasting it
        self._ssid_bssid_map: dict = defaultdict(set)

    def inspect(self, packet: dict) -> tuple | None:
        """
        Inspect a packet for Evil Twin behaviour.

        Returns:
            (attack_type, severity, details) tuple if evil twin detected, else None.
        """
        ssid = packet.get("ssid", "").strip()
        bssid = packet.get("bssid", "").upper()

        if not ssid or ssid in ("unknown", ""):
            return None

        known_bssids = self._ssid_bssid_map[ssid]

        if known_bssids and bssid not in known_bssids:
            result = (
                "Evil Twin Attack",
                "High",
                f"SSID '{ssid}' is broadcasting from BSSID {bssid} "
                f"in addition to known BSSID(s): {', '.join(known_bssids)}",
            )
            known_bssids.add(bssid)
            return result

        known_bssids.add(bssid)
        return None
