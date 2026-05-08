"""
Wireless Intrusion Detection System (WIDS) — Main Entry Point

Trains the ML models on the user-supplied wids_threat_logs.csv dataset and
runs the full detection pipeline on the same records, producing a fresh
threat log in logs/threat_logs.csv.

Usage:
    python main.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from packet_processing.packet_capture   import load_dataset_packets
from packet_processing.feature_extraction import extract_features
from feature_engineering.feature_fusion  import FeatureFusion
from detection_engine.detection_engine   import DetectionEngine
from alert_system.alert_system           import AlertSystem


def main():
    print("=" * 62)
    print("  Wireless Intrusion Detection System (WIDS)")
    print("  Mode: Dataset Training + Detection")
    print("=" * 62)

    # ---------------------------------------------------------------- load
    raw_packets = load_dataset_packets(max_packets=2000)
    if not raw_packets:
        print("[WIDS] No packets loaded. Aborting.")
        sys.exit(1)

    # ---------------------------------------------------------------- extract features
    print(f"\n[WIDS] Extracting features from {len(raw_packets)} records ...")
    extracted = [extract_features(p) for p in raw_packets]

    # ---------------------------------------------------------------- build fused training vectors
    print("[WIDS] Building fused training vectors ...")
    train_fusion = FeatureFusion(window_size=50)
    training_vectors = []
    for pkt in extracted:
        train_fusion.update(pkt)
        training_vectors.append(train_fusion.fuse(pkt))

    # ---------------------------------------------------------------- set up engine
    engine      = DetectionEngine()
    alert_sys   = AlertSystem()
    run_fusion  = FeatureFusion(window_size=50)

    # Register first 10 % of packets as trusted baseline for rule engine
    baseline_count = max(1, len(extracted) // 10)
    for pkt in extracted[:baseline_count]:
        engine.learn_baseline(pkt)
    print(f"[WIDS] Baseline registered: {baseline_count} packets.")

    # ---------------------------------------------------------------- train ML
    print(f"[WIDS] Training ML models on {len(training_vectors)} vectors ...")
    engine.train_ml(training_vectors)

    # ---------------------------------------------------------------- run detection
    print(f"\n[WIDS] Running detection pipeline on {len(raw_packets)} dataset records ...")
    print("=" * 62)

    detected_count = 0
    for pkt in raw_packets:
        features = extract_features(pkt)
        run_fusion.update(features)
        fused = run_fusion.fuse(features)
        alerts = engine.analyze(fused)
        for attack_type, severity, details in alerts:
            alert_sys.trigger_alert(attack_type, severity, details)
            detected_count += 1

    # ---------------------------------------------------------------- summary
    alert_sys.summary()
    print(f"[WIDS] Detections fired  : {detected_count}")
    print(f"[WIDS] Dataset records   : {len(raw_packets)}")
    print(f"[WIDS] Logs saved to     : logs/threat_logs.csv")
    print("=" * 62)


if __name__ == "__main__":
    main()
