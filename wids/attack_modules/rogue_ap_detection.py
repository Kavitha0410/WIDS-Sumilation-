"""
Rogue AP Detection Module
Detects unauthorized access points broadcasting on the network.
A rogue AP is any BSSID that has not been registered as trusted.
"""


class RogueAPDetection:
    """Maintains a whitelist of trusted BSSIDs and flags unknown ones."""

    def __init__(self, trusted_bssids: set = None):
        self._trusted: set = set(trusted_bssids) if trusted_bssids else set()

    def register_trusted(self, bssid: str):
        """Add a BSSID to the trusted whitelist."""
        self._trusted.add(bssid.upper())

    def inspect(self, packet: dict) -> tuple | None:
        """
        Inspect a packet's BSSID against the trusted list.

        Returns:
            (attack_type, severity, details) tuple if rogue AP detected, else None.
        """
        bssid = packet.get("bssid", "").upper()
        if not bssid or bssid == "00:00:00:00:00:00":
            return None

        if self._trusted and bssid not in self._trusted:
            return (
                "Rogue AP Detected",
                "Medium",
                f"BSSID {bssid} is not in the trusted AP list",
            )
        return None
