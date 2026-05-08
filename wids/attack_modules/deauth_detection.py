"""
Deauthentication Attack Detection Module
Specialized detector for 802.11 deauthentication flood attacks.
A deauth flood forces clients off the network by sending spoofed deauth frames.
"""

from collections import defaultdict


class DeauthDetection:
    """Tracks deauthentication frames per source MAC and flags flood attacks."""

    THRESHOLD = 10  # Deauth frames within the session window

    def __init__(self):
        self._deauth_counts: dict = defaultdict(int)

    def inspect(self, packet: dict) -> tuple | None:
        """
        Inspect a single packet for deauth flood behaviour.

        Returns:
            (attack_type, severity, details) tuple if attack detected, else None.
        """
        if packet.get("subtype", "").lower() != "deauth":
            return None

        src_mac = packet.get("src_mac", "unknown")
        self._deauth_counts[src_mac] += 1

        if self._deauth_counts[src_mac] >= self.THRESHOLD:
            return (
                "Deauthentication Attack",
                "High",
                f"MAC {src_mac} has sent {self._deauth_counts[src_mac]} deauth frames",
            )
        return None
