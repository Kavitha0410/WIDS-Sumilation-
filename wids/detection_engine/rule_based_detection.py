"""
Rule-Based Detection Engine
Implements threshold and heuristic rules for detecting common Wi-Fi attacks.
Each rule inspects the fused feature vector and returns a detection result.
"""

from collections import defaultdict


class RuleBasedDetection:
    """
    Stateful rule engine that tracks per-session counters and known device
    mappings in memory to detect anomalous behaviour patterns.
    """

    # Thresholds (tunable)
    DEAUTH_THRESHOLD = 10       # Deauth frames per rolling window to flag an attack
    PROBE_THRESHOLD = 15        # Probe requests per MAC to flag as suspicious

    def __init__(self):
        # src_mac -> deauth count
        self._deauth_counter: dict = defaultdict(int)
        # src_mac -> set of MACs seen for the same SSID
        self._ssid_bssid_map: dict = defaultdict(set)
        # set of known / trusted BSSIDs (populated from first N packets)
        self._known_bssids: set = set()
        # src_mac -> set of MACs it has used
        self._mac_history: dict = defaultdict(set)

    def learn(self, packet: dict):
        """
        Register a packet as 'baseline normal' to populate known-good sets.
        Call this on non-attack traffic before entering detection mode.
        """
        self._known_bssids.add(packet.get("bssid", ""))
        self._mac_history[packet.get("src_mac", "")].add(packet.get("src_mac", ""))

    def detect(self, packet: dict) -> list:
        """
        Run all rules against a single fused packet.

        Returns:
            List of (attack_type, severity, details) tuples for any triggered rules.
        """
        alerts = []
        src_mac = packet.get("src_mac", "")
        bssid = packet.get("bssid", "")
        ssid = packet.get("ssid", "")
        subtype = packet.get("subtype", "")
        deauth_ratio = packet.get("deauth_ratio", 0)
        freq = packet.get("packet_frequency", 0)

        alerts += self._rule_deauth(src_mac, subtype, deauth_ratio)
        alerts += self._rule_evil_twin(ssid, bssid)
        alerts += self._rule_rogue_ap(bssid)
        alerts += self._rule_mac_spoofing(src_mac, bssid)

        return alerts

    # ------------------------------------------------------------------ rules

    def _rule_deauth(self, src_mac: str, subtype: str, deauth_ratio: float) -> list:
        """
        Detect deauthentication flood attacks.
        Triggers when deauth ratio in the window exceeds the threshold.
        """
        if subtype == "deauth":
            self._deauth_counter[src_mac] += 1

        if deauth_ratio > 0.3 or self._deauth_counter[src_mac] > self.DEAUTH_THRESHOLD:
            return [
                (
                    "Deauthentication Attack",
                    "High",
                    f"MAC {src_mac} sent excessive deauth frames "
                    f"(window ratio={deauth_ratio:.2f}, count={self._deauth_counter[src_mac]})",
                )
            ]
        return []

    def _rule_evil_twin(self, ssid: str, bssid: str) -> list:
        """
        Detect Evil Twin APs: same SSID but a BSSID not seen before for that SSID.
        """
        if ssid == "unknown" or not ssid:
            return []

        known = self._ssid_bssid_map[ssid]
        if known and bssid not in known:
            return [
                (
                    "Evil Twin Attack",
                    "High",
                    f"SSID '{ssid}' seen with new BSSID {bssid} "
                    f"(known BSSIDs: {', '.join(known)})",
                )
            ]
        self._ssid_bssid_map[ssid].add(bssid)
        return []

    def _rule_rogue_ap(self, bssid: str) -> list:
        """
        Detect Rogue APs: a BSSID that is not in the known-good set.
        """
        if self._known_bssids and bssid not in self._known_bssids:
            return [
                (
                    "Rogue AP Detected",
                    "Medium",
                    f"Unknown BSSID {bssid} is not in the trusted list",
                )
            ]
        return []

    def _rule_mac_spoofing(self, src_mac: str, bssid: str) -> list:
        """
        Detect MAC spoofing: a device using multiple BSSIDs (indicative of
        a device that changes its identity).
        """
        self._mac_history[src_mac].add(bssid)
        if len(self._mac_history[src_mac]) > 3:
            return [
                (
                    "MAC Spoofing Detected",
                    "Medium",
                    f"MAC {src_mac} has been associated with "
                    f"{len(self._mac_history[src_mac])} different BSSIDs",
                )
            ]
        return []

    def reset(self):
        """Clear all stateful counters."""
        self._deauth_counter.clear()
        self._ssid_bssid_map.clear()
        self._known_bssids.clear()
        self._mac_history.clear()
