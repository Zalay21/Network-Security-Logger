# Network Security Logger

A Python tool that monitors network traffic in real time, detects suspicious patterns (e.g., plain-text occurrences of "password", "credit card", etc.), logs information, and exports logs to JSON for analysis.

## Features

- Captures live network packets using PyShark (built on Wireshark).
- Logs system details (hostname, local IP).
- Alerts when suspicious patterns are detected in HTTP payloads.
- Exports captured log events to structured JSON for post-analysis.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Wireshark installed with `tshark` accessible
- Python library: `pyshark`

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Zalay21/Network-Security-Logger.git
cd Network-Security-Logger
pip install pyshark
```

### Usage

1. Run the script:

```bash
python network_monitor.py
```

2. When prompted, enter the network interface to monitor (e.g., `eth0`, `wlan0`).

3. When prompted, specify a filename to export the logs as JSON (e.g., `output.json`).

The tool will capture a limited number of packets (defined in the script), log system information, and record suspicious patterns to `network_security_logger.log`. After capture, logs are exported to the specified JSON file.

## Future Enhancements

- Support additional protocols (FTP, SSH, DNS, etc.).
- Real-time alerts via email or messaging services.
- Persist logs to a database for long-term analysis.
- Interactive GUI for non-technical users.
