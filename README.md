# Wireless Intrusion Detection System (WIDS)

A modular Python system that detects Wi-Fi attacks using rule-based heuristics and machine learning.

---

## Quick Start — Web Dashboard (Recommended)

Run the full web dashboard with one command. Your browser opens automatically.

**Windows (PowerShell):**
```powershell
cd wids
pip install -r requirements.txt
python dashboard/app.py
```

**Mac / Linux:**
```bash
cd wids
pip install -r requirements.txt
python dashboard/app.py
```

Your browser will open at **http://localhost:5000** automatically.

The dashboard includes:
- **Dashboard** — threat counts, activity chart, recent alerts
- **Live Monitor** — real-time packet feed
- **Attack Simulator** — trigger deauth, evil twin, rogue AP, MAC spoof attacks
- **Logs & Analytics** — full searchable log table with charts
- **Settings** — configure detection thresholds

No Node.js required — the frontend is pre-built and served directly by Flask.

---

## Terminal-Only Mode (no browser)

If you only want to see packet alerts printed in the terminal:

```bash
python main.py
```

This runs the detection pipeline and prints alerts to the console, saving results to `logs/threat_logs.csv`.

---

## Command Reference

| Command | What it does |
|---|---|
| `python main.py` | Run all 4 simulated attacks (default) |
| `python main.py --simulate` | Same as above |
| `python main.py --simulate --type deauth` | Simulate deauth attack only |
| `python main.py --simulate --type evil_twin` | Simulate evil twin only |
| `python main.py --simulate --type rogue_ap` | Simulate rogue AP only |
| `python main.py --simulate --type mac_spoof` | Simulate MAC spoofing only |

---

## Attacks Detected

| Attack | Method |
|---|---|
| Deauthentication flood | Rule-based (frame count threshold) + ML |
| Evil Twin AP | Rule-based (SSID/BSSID mismatch) + ML |
| Rogue AP | Rule-based (unknown BSSID whitelist) + ML |
| MAC Spoofing | Rule-based (MAC-to-BSSID history) + ML |
| Unknown anomalies | IsolationForest (unsupervised ML) |

---

## Project Structure

```
wids/
├── main.py                         # Main entry point
├── requirements.txt
├── dashboard/
│   └── app.py                      # Flask web dashboard (localhost:5000)
├── packet_processing/
│   ├── packet_capture.py           # Packet loader
│   └── feature_extraction.py      # Field normalization
├── feature_engineering/
│   └── feature_fusion.py          # Rolling-window feature enrichment
├── detection_engine/
│   ├── detection_engine.py        # Orchestrator (rule + ML)
│   ├── rule_based_detection.py    # Threshold / heuristic rules
│   └── ml_detection.py            # RandomForest + IsolationForest
├── attack_modules/
│   ├── deauth_detection.py
│   ├── rogue_ap_detection.py
│   ├── mac_spoofing_detection.py
│   └── evil_twin_detection.py
├── attack_simulator/
│   ├── simulate_deauth.py
│   ├── simulate_evil_twin.py
│   ├── simulate_rogue_ap.py
│   └── simulate_mac_spoof.py
├── alert_system/
│   └── alert_system.py
├── logging_system/
│   └── logger.py
└── logs/
    └── threat_logs.csv            # Auto-generated on first run
```

---

## Dependencies

```
pandas        — Packet data handling
numpy         — Numeric feature matrices
scikit-learn  — RandomForestClassifier, IsolationForest
flask         — Web dashboard
```

Install with:

```bash
pip install -r requirements.txt
```
