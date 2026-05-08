"""
WIDS Flask Dashboard
Serves the full React-based WIDS web app locally.

Run with:
    cd wids
    python dashboard/app.py

Your browser will open automatically at http://localhost:5000
"""

import os
import sys
import threading
import webbrowser
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, jsonify, send_from_directory, request
from logging_system.logger import get_logs, LOG_FILE

DIST_DIR = os.path.join(os.path.dirname(__file__), "dist")

app = Flask(__name__, static_folder=DIST_DIR, static_url_path="")


def _auto_seed_if_empty():
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 50:
        return
    print("[Dashboard] No log file found. Running initial simulation to seed data...")
    print("[Dashboard] This takes a few seconds on first launch only.\n")
    try:
        from packet_processing.feature_extraction import extract_features
        from feature_engineering.feature_fusion import FeatureFusion
        from detection_engine.detection_engine import DetectionEngine
        from alert_system.alert_system import AlertSystem
        from attack_simulator.simulate_deauth import simulate_deauth
        from attack_simulator.simulate_evil_twin import simulate_evil_twin
        from attack_simulator.simulate_rogue_ap import simulate_rogue_ap
        from attack_simulator.simulate_mac_spoof import simulate_mac_spoof

        packets = (
            simulate_deauth(count=20, ssid="HomeNet")
            + simulate_evil_twin(count=10, ssid="HomeNet",
                                  legitimate_bssid="AA:BB:CC:DD:EE:00")
            + simulate_rogue_ap(count=10, ssid="FreePublicWiFi")
            + simulate_mac_spoof(count=15, target_ssid="HomeNet")
        )

        fusion = FeatureFusion(window_size=50)
        engine = DetectionEngine()
        alert_sys = AlertSystem(use_color=False)

        extracted = [extract_features(p) for p in packets]
        sf = FeatureFusion(window_size=50)
        training = []
        for p in extracted:
            sf.update(p)
            training.append(sf.fuse(p))
        engine.train_ml(training)

        for pkt in packets:
            f = extract_features(pkt)
            fusion.update(f)
            fused = fusion.fuse(f)
            for at, sev, det in engine.analyze(fused):
                alert_sys.trigger_alert(at, sev, det)

        print(f"\n[Dashboard] Seeded {len(get_logs())} threat entries. Dashboard is ready.\n")
    except Exception as exc:
        print(f"[Dashboard] Seeding failed: {exc}")


_auto_seed_if_empty()


# ─── in-memory state ────────────────────────────────────────────────────────

_system_status = "running"
_started_at = __import__("time").time()
_total_packets = 0

_settings = {
    "ml_detection_enabled": True,
    "rule_based_detection_enabled": True,
    "alert_threshold": "Medium",
    "auto_refresh_interval": 3,
}


# ─── API routes ─────────────────────────────────────────────────────────────

@app.route("/api/wids/logs")
def api_logs():
    logs = get_logs()
    return jsonify({"logs": logs, "total": len(logs)})


@app.route("/api/wids/status")
def api_status():
    import time
    return jsonify({
        "status": _system_status,
        "uptime_seconds": int(time.time() - _started_at),
        "total_packets_processed": _total_packets,
    })


@app.route("/api/wids/status/toggle", methods=["POST"])
def api_toggle():
    global _system_status, _started_at
    import time
    body = request.get_json(silent=True) or {}
    action = body.get("action", "start")
    if action == "start":
        _system_status = "running"
        _started_at = time.time()
    else:
        _system_status = "stopped"
    return jsonify({
        "status": _system_status,
        "uptime_seconds": int(time.time() - _started_at),
        "total_packets_processed": _total_packets,
    })


VALID_ATTACK_TYPES = {"deauth", "evil_twin", "rogue_ap", "mac_spoof", "all"}

SIMULATORS = {
    "deauth":     lambda: __import__("attack_simulator.simulate_deauth",   fromlist=["simulate_deauth"]).simulate_deauth(count=20, ssid="HomeNet"),
    "evil_twin":  lambda: __import__("attack_simulator.simulate_evil_twin", fromlist=["simulate_evil_twin"]).simulate_evil_twin(count=10, ssid="HomeNet", legitimate_bssid="AA:BB:CC:DD:EE:00"),
    "rogue_ap":   lambda: __import__("attack_simulator.simulate_rogue_ap",  fromlist=["simulate_rogue_ap"]).simulate_rogue_ap(count=10, ssid="FreePublicWiFi"),
    "mac_spoof":  lambda: __import__("attack_simulator.simulate_mac_spoof", fromlist=["simulate_mac_spoof"]).simulate_mac_spoof(count=15, target_ssid="HomeNet"),
}


@app.route("/api/wids/simulate", methods=["POST"])
def api_simulate():
    global _total_packets
    body = request.get_json(silent=True) or {}
    attack_type = body.get("attack_type", "all")

    if attack_type not in VALID_ATTACK_TYPES:
        return jsonify({"success": False, "message": "Unknown attack type",
                        "new_detections": 0, "attack_type": attack_type}), 400

    try:
        from packet_processing.feature_extraction import extract_features
        from feature_engineering.feature_fusion import FeatureFusion
        from detection_engine.detection_engine import DetectionEngine
        from alert_system.alert_system import AlertSystem

        if attack_type == "all":
            packets = []
            for fn in SIMULATORS.values():
                packets += fn()
        else:
            packets = SIMULATORS[attack_type]()

        fusion = FeatureFusion(window_size=50)
        engine = DetectionEngine()
        alert_sys = AlertSystem(use_color=False)

        extracted = [extract_features(p) for p in packets]
        sf = FeatureFusion(window_size=50)
        training = []
        for p in extracted:
            sf.update(p)
            training.append(sf.fuse(p))
        engine.train_ml(training)

        count = 0
        for pkt in packets:
            f = extract_features(pkt)
            fusion.update(f)
            fused = fusion.fuse(f)
            for at, sev, det in engine.analyze(fused):
                alert_sys.trigger_alert(at, sev, det)
                count += 1

        _total_packets += len(packets)
        label = "All attacks" if attack_type == "all" else attack_type.replace("_", " ")
        return jsonify({"success": True, "message": f"{label} simulation complete",
                        "new_detections": count, "attack_type": attack_type})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc),
                        "new_detections": 0, "attack_type": attack_type}), 500


@app.route("/api/wids/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        for key in _settings:
            if key in body:
                _settings[key] = body[key]
    return jsonify(_settings)


# ─── Serve React frontend ────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    full = os.path.join(DIST_DIR, path)
    if path and os.path.isfile(full):
        return send_from_directory(DIST_DIR, path)
    return send_from_directory(DIST_DIR, "index.html")


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    url = f"http://127.0.0.1:{port}"

    print(f"\n{'='*55}")
    print(f"  WIDS Dashboard starting...")
    print(f"  Opening browser at: {url}")
    print(f"  Press Ctrl+C to stop.")
    print(f"{'='*55}\n")

    def _open_browser():
        import time
        time.sleep(1.2)
        webbrowser.open(url)

    threading.Thread(target=_open_browser, daemon=True).start()
    app.run(debug=False, host="0.0.0.0", port=port)
