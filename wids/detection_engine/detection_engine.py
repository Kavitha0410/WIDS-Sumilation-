"""
Detection Engine (Orchestrator)
Combines rule-based and ML detection into a single pipeline step.
Receives a fused feature vector, queries both engines, deduplicates results,
and returns a unified list of alert tuples.
"""

from detection_engine.rule_based_detection import RuleBasedDetection
from detection_engine.ml_detection import MLDetection


class DetectionEngine:
    """
    Central detection orchestrator. Delegates to rule-based and ML sub-engines
    and deduplicates overlapping alerts so the user doesn't see duplicates.
    """

    def __init__(self):
        self.rule_engine = RuleBasedDetection()
        self.ml_engine = MLDetection()

    def train_ml(self, packets: list):
        """Train the ML model on a list of fused feature packets."""
        self.ml_engine.train(packets)

    def learn_baseline(self, packet: dict):
        """Register a packet as trusted baseline traffic."""
        self.rule_engine.learn(packet)

    def analyze(self, packet: dict) -> list:
        """
        Run full detection on a single fused packet.

        Returns:
            Deduplicated list of (attack_type, severity, details) tuples.
        """
        rule_alerts = self.rule_engine.detect(packet)
        ml_alerts = self.ml_engine.predict(packet)

        # Merge and deduplicate by attack_type
        seen = set()
        merged = []
        for alert in rule_alerts + ml_alerts:
            key = alert[0]  # attack_type is the dedup key
            if key not in seen:
                seen.add(key)
                merged.append(alert)

        return merged

    def reset(self):
        """Reset the rule engine's stateful counters."""
        self.rule_engine.reset()
