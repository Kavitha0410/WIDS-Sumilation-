"""
Machine Learning Detection Engine
Uses RandomForestClassifier (supervised) and IsolationForest (unsupervised)
trained on packet feature vectors to detect known and unknown attack patterns.
All data lives in memory — no external database required.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder


class MLDetection:
    """
    Two-model ML detection layer:
    - RandomForest: supervised classifier trained on labelled dataset packets
    - IsolationForest: anomaly detector that flags unusual traffic patterns
    """

    # Feature columns extracted from fused packet dicts
    NUMERIC_FEATURES = ["rssi", "packet_frequency", "avg_rssi",
                        "deauth_ratio", "beacon_ratio", "probe_ratio"]

    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.iso_model = IsolationForest(contamination=0.1, random_state=42)
        self.label_encoder = LabelEncoder()
        self._trained = False

    # ---------------------------------------------------------------- training

    def train(self, packets: list):
        """
        Train both models on a list of fused packet dictionaries.
        Requires at least 2 distinct labels to fit the classifier.

        Args:
            packets: List of fused feature dicts (must include 'label' key)
        """
        if len(packets) < 5:
            print("[MLDetection] Not enough samples to train. Skipping ML training.")
            return

        X = self._extract_matrix(packets)
        labels = [p.get("label", "normal") for p in packets]

        # Ensure there are at least 2 distinct classes
        unique_labels = list(set(labels))
        if len(unique_labels) < 2:
            # Inject a synthetic minority-class sample so the encoder has two classes
            labels[0] = "attack" if labels[0] == "normal" else "normal"

        y = self.label_encoder.fit_transform(labels)

        self.rf_model.fit(X, y)
        self.iso_model.fit(X)
        self._trained = True
        print(f"[MLDetection] Models trained on {len(packets)} samples "
              f"({len(unique_labels)} distinct labels).")

    # ---------------------------------------------------------------- inference

    def predict(self, packet: dict) -> list:
        """
        Run ML inference on a single fused packet.

        Returns:
            List of (attack_type, severity, details) tuples for any detections.
        """
        if not self._trained:
            return []

        alerts = []
        X = self._extract_matrix([packet])

        # Supervised classification
        rf_pred = self.rf_model.predict(X)[0]
        label = self.label_encoder.inverse_transform([rf_pred])[0]
        if label != "normal":
            proba = self.rf_model.predict_proba(X)[0].max()
            alerts.append((
                f"ML-Detected Attack ({label})",
                "High",
                f"RandomForest classified packet as '{label}' "
                f"with confidence {proba:.0%}",
            ))

        # Anomaly detection
        iso_pred = self.iso_model.predict(X)[0]
        if iso_pred == -1:
            alerts.append((
                "Anomalous Traffic (ML)",
                "Medium",
                "IsolationForest flagged this packet as an anomaly",
            ))

        return alerts

    # ----------------------------------------------------------------- helpers

    def _extract_matrix(self, packets: list) -> np.ndarray:
        """Convert a list of fused packet dicts to a numeric feature matrix."""
        rows = []
        for p in packets:
            row = [float(p.get(f, 0.0)) for f in self.NUMERIC_FEATURES]
            rows.append(row)
        return np.array(rows, dtype=float)

    @property
    def is_trained(self) -> bool:
        return self._trained
