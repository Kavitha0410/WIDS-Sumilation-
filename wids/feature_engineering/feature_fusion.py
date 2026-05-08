"""
Feature Fusion Module
Combines packet-level fields with session-level statistics (frequency,
signal strength, frame type distribution) to produce a unified feature
vector used by both the rule-based and ML detection engines.
"""

from collections import Counter


class FeatureFusion:
    """
    Maintains a rolling window of observed packets and exposes methods to
    compute fused feature vectors for a given packet.
    """

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._history: list = []  # Sliding window of recent packets

    def update(self, packet: dict):
        """Add a new packet to the rolling window."""
        self._history.append(packet)
        if len(self._history) > self.window_size:
            self._history.pop(0)

    def fuse(self, packet: dict) -> dict:
        """
        Compute a fused feature vector for the given packet, enriched with
        statistics derived from the current sliding window.

        Returns:
            dict with keys:
                src_mac, dst_mac, bssid, ssid, frame_type, subtype,
                rssi, label,
                packet_frequency  - how many times this src_mac appears in window
                avg_rssi          - average RSSI across all packets in window
                deauth_ratio      - fraction of window packets that are deauth
                beacon_ratio      - fraction of window packets that are beacons
                probe_ratio       - fraction of window packets that are probes
        """
        total = max(len(self._history), 1)

        src_mac = packet.get("src_mac", "")
        subtypes = [p.get("subtype", "") for p in self._history]
        rssi_values = [p.get("rssi", -100) for p in self._history]

        subtype_counts = Counter(subtypes)
        mac_count = sum(1 for p in self._history if p.get("src_mac") == src_mac)

        fused = dict(packet)
        fused["packet_frequency"] = mac_count
        fused["avg_rssi"] = sum(rssi_values) / total
        fused["deauth_ratio"] = subtype_counts.get("deauth", 0) / total
        fused["beacon_ratio"] = subtype_counts.get("beacon", 0) / total
        fused["probe_ratio"] = subtype_counts.get("probe_request", 0) / total

        return fused

    def reset(self):
        """Clear the packet history."""
        self._history.clear()
