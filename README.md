# 📡 Network Security Logger

A Python-based network monitoring tool that captures live traffic, detects suspicious patterns in HTTP payloads, and exports structured logs for security analysis. Built on top of **PyShark** (Wireshark/tshark) for real packet capture.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat&logo=python&logoColor=white)
![Wireshark](https://img.shields.io/badge/Built_on-Wireshark%2Ftshark-1679A7?style=flat&logo=wireshark&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## Features

- **Live Packet Capture** — Monitors network interfaces in real time using PyShark's `LiveCapture`
- **Suspicious Pattern Detection** — Scans HTTP payloads for sensitive data patterns: `password`, `credit card`, `ssn`
- **Structured Logging** — Logs all events with timestamps and severity levels to a `.log` file
- **JSON Export** — Converts captured logs to structured JSON for integration with SIEM tools or manual analysis
- **System Info Logging** — Records hostname, local IP, OS, and timestamp at startup for forensic context

---

## Project Structure

```
Network-Security-Logger/
├── network_monitor.py           # Main monitoring script
├── network_security_logger.log  # Generated at runtime — raw log output
├── LICENSE                      # MIT License
└── README.md
```

---

## Installation

**Prerequisites:**
- Python 3.8+
- Wireshark / tshark installed and accessible in PATH
- Root or sudo privileges (required for packet capture)

```bash
# Clone the repository
git clone https://github.com/Zalay21/Network-Security-Logger.git
cd Network-Security-Logger

# Install Python dependencies
pip install pyshark

# Verify tshark is available
tshark --version
```

> **Kali Linux / Debian:** tshark comes pre-installed with Wireshark. Install with `sudo apt install tshark` if needed.

---

## Usage

```bash
# Run with elevated privileges (required for packet capture)
sudo python network_monitor.py
```

### Interactive Prompts

```
Enter network interface to monitor (e.g., 'eth0', 'wlan0'): eth0
```

The tool captures up to **100 packets** (configurable in source), analyzes HTTP traffic for suspicious patterns, and logs everything.

```
Enter filename to export logs as JSON (e.g., 'output.json'): capture_log.json
Network monitoring completed and logs exported.
```

### Example Log Output

**Raw log** (`network_security_logger.log`):
```
2025-03-14 22:15:03,421 - INFO - System Info: {"hostname": "kali", "local_ip": "192.168.1.105", "date": "2025-03-14T22:15:03", "os": "posix"}
2025-03-14 22:15:04,892 - INFO - Starting packet capture on interface eth0
2025-03-14 22:15:05,210 - INFO - HTTP Packet captured: GET /api/users HTTP/1.1
2025-03-14 22:15:06,334 - WARNING - Suspicious pattern detected: password in packet: login_form&password=hunter2
```

**Exported JSON** (`capture_log.json`):
```json
[
    {
        "timestamp": "2025-03-14 22:15:03,421",
        "level": "INFO",
        "message": "System Info: {\"hostname\": \"kali\", \"local_ip\": \"192.168.1.105\"...}"
    },
    {
        "timestamp": "2025-03-14 22:15:06,334",
        "level": "WARNING",
        "message": "Suspicious pattern detected: password in packet: login_form&password=hunter2"
    }
]
```

---

## How It Works

```
┌──────────────────┐
│  Network Traffic  │
│   (eth0/wlan0)   │
└────────┬─────────┘
         │
    ┌────▼────┐
    │ PyShark  │  ← tshark backend
    │ Capture  │
    └────┬────┘
         │
    ┌────▼─────────────┐
    │ Packet Analysis   │
    │ - HTTP inspection │
    │ - Pattern match   │
    │   (password, ssn, │
    │    credit card)   │
    └────┬─────────────┘
         │
    ┌────▼──────────┐     ┌──────────────┐
    │ Python Logger  │────►│  .log file   │
    │  (INFO/WARN)   │     └──────┬───────┘
    └────────────────┘            │
                            ┌─────▼──────┐
                            │ JSON Export │
                            │ (SIEM-ready)│
                            └────────────┘
```

---

## Technologies

| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Packet Capture | PyShark (Python wrapper for tshark/Wireshark) |
| Logging | Python `logging` module |
| Export Format | JSON |
| Network Analysis | HTTP payload inspection with pattern matching |

---

## Use Cases

- **Lab Training** — Practice network monitoring and traffic analysis in a home lab
- **Security Auditing** — Detect plaintext credentials being transmitted over HTTP
- **Incident Response** — Capture and export traffic logs during a security investigation
- **Learning Tool** — Understand how packet capture and network analysis tools work under the hood

---

## Future Enhancements

- [ ] Support additional protocols (FTP, DNS, SMTP, SSH)
- [ ] Real-time alerts via email or webhook notifications
- [ ] Configurable pattern lists via external config file
- [ ] Database storage for long-term log retention
- [ ] Interactive dashboard for visualization
- [ ] Packet filtering by source/destination IP

---

## Author

**Za Lay** — [GitHub](https://github.com/Zalay21) · [LinkedIn](https://linkedin.com/in/zalay0021) · [zalay0021@gmail.com](mailto:zalay0021@gmail.com)
