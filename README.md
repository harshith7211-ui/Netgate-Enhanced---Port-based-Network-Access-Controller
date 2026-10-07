# Network Monitor

A Flask-based network traffic monitor with packet capture, device labeling, statistics, DNS resolution, and HTML reporting.

## Features

1. **Device IP Labeling** - Map IPs to friendly names via `device_labels.txt`
2. **Statistics Report** - Track allowed/blocked packets, top ports, protocols, IPs
3. **DNS Resolution** - Show domain names instead of IPs (cached)
4. **HTML Report** - Auto-generates `report.html` on stop (Ctrl+C or button)

## Requirements

- Python 3.8+
- Flask 3.0+
- Scapy 2.5+
- **Npcap** (Windows) or **libpcap** (Linux/macOS) for packet capture

### Windows Setup
1. Install Npcap: https://npcap.com/ (check "Install Npcap in WinPcap API-compatible Mode")
2. Run as Administrator for packet capture

### Linux/macOS Setup
```bash
sudo apt-get install libpcap-dev  # or: brew install libpcap
pip install -r requirements.txt
sudo python app.py  # needs root for promiscuous mode
```

## Installation

```bash
cd network_monitor
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

Open http://localhost:5001

## Usage

1. **Start Capture** - Click "Start Capture" to begin monitoring
2. **View Dashboard** - Real-time stats: packets, allowed/blocked, top ports, domains, IPs
3. **Device Labels** - Click "Device Labels" to map IPs to names (saved to `device_labels.txt`)
4. **Stop Capture** - Click "Stop Capture" or press Ctrl+C to generate `report.html`
5. **View Report** - Click "View Report" for full HTML report

## Files

```
network_monitor/
├── app.py              # Main Flask app
├── device_labels.txt   # IP=Label mappings
├── requirements.txt    # Dependencies
├── templates/
│   └── dashboard.html  # Web UI
├── report.html         # Generated on stop
└── monitor.db          # (optional) SQLite for persistence
```

## API Endpoints

- `GET /` - Dashboard
- `POST /api/start` - Start packet capture
- `POST /api/stop` - Stop capture, generate report
- `GET /api/status` - Current statistics
- `GET /api/labels` - Get device labels
- `POST /api/labels` - Save device labels
- `GET /api/report` - Get generated HTML report

## Classification Rules

Packets are classified as **blocked** if destination port is in:
- 23 (Telnet), 135 (RPC), 139 (NetBIOS), 445 (SMB)
- 1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC)

Modify `classify_packet()` in `app.py` for custom rules.

## Notes

- DNS resolution is cached in-memory (survives restarts via `dns_cache`)
- Run as Administrator/root for full packet capture
- On Windows, Npcap must be installed in WinPcap-compatible mode