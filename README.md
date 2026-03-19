# SentinelXDR-PyAgent

**Sentinel XDR Python Agent** is a **real-time host security monitoring platform** built in Python.  
It simulates the core functionality of an enterprise XDR agent, including **file integrity monitoring, process telemetry, anomaly detection, threat scoring, and a live dashboard** for actionable insights.

---

## 🚀 Features

### Real-Time Monitoring
- Tracks file system changes (`created`, `modified`, `deleted`) in monitored directories.
- Monitors process activity including suspicious commands (`CMD`, `PowerShell`).
- Detects **anomalous behavior** via burst detection and rapid event scoring.

### Threat Detection & Scoring
- Assigns **threat scores** to events (e.g., high for command prompt launches or file deletions).
- Maintains **critical event buffer** for immediate attention.
- Highlights high-severity events in the dashboard.

### Live Dashboard
- Built using **Dash & Plotly**.
- Displays:
  - **Uptime**, total events, critical events (KPIs)
  - **Timeline chart** of all events
  - **Event type breakdown** (pie chart)
  - **Live logs** for critical and all events
- Provides an **interactive view** of host security metrics in real-time.

### Logging & Persistence
- Events are logged in `siem_events.log`.
- Maintains history in memory buffers for quick access.
- Supports audit and investigation workflow simulation.

---

## 🛠 Installation

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/SentinelXDR-PyAgent.git
cd SentinelXDR-PyAgent
````

2. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ⚡ Usage

Run the Python agent:

```bash
python SentinelXDR.py
```

Open your browser at:

```
http://127.0.0.1:8050
```

You’ll see the **live monitoring dashboard** with KPIs, charts, and logs.

---

## 📝 Configuration

* By default, it monitors the **user’s home directory** (`MONITORED_DIR`).
* Ignore certain files/directories via `IGNORED_EXTENSIONS` and `IGNORED_KEYWORDS`.
* Threat scoring is configurable in `THREAT_SCORES` dictionary.
* Buffers for events are controlled via `MAX_EVENT_BUFFER` and `MAX_CRITICAL_EVENTS`.

---

## 📊 Enterprise Simulation

This project simulates enterprise XDR behavior:

* Event correlation via burst detection.
* Threat prioritization for security operations.
* Real-time dashboard for SOC-style monitoring.
* Threaded design for performance and responsiveness.

> Note: This is a **simulation/portfolio project**. It does not perform real endpoint remediation.

---

## 🔧 Dependencies

* Python 3.8+
* dash
* plotly
* pandas
* psutil
* watchdog

---

## 📁 File Structure

```
SentinelXDR-PyAgent/
├── SentinelXDR.py       # Main agent & dashboard
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

---

## 📜 License

MIT License

---

## ⭐ Suggested Improvements for Enterprise Use

* Add **network telemetry monitoring** (IP connections, ports, suspicious traffic).
* Integrate **response actions** (quarantine files, block IPs).
* Store events in **structured database** (SQLite/PostgreSQL) instead of CSV/log file.
* Add **configurable detection rules** in JSON/YAML for modularity.

```


