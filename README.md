
# Network Security Logger

A Python-based network security tool that captures and analyzes network traffic, detects suspicious patterns, and exports logs in JSON format. This project is ideal for learning and showcasing skills in network monitoring and security analysis.

## Features

- Logs system and network information.
- Monitors live network traffic using the `pyshark` library.
- Detects suspicious patterns in HTTP packets (e.g., `password`, `credit card`, etc.).
- Exports logs as a structured JSON file for further analysis.

## Prerequisites

- Python 3.8 or higher
- Wireshark installed
- Required Python libraries:
  - `pyshark`
  - `json`

### Install Dependencies
Run the following command to install the required libraries:
```bash
pip install pyshark
```

## Usage

1. Clone the repository:
```bash
git clone https://github.com/Zalay21/Network-Security-Logger.git
cd Network-Security-Logger
```

2. Run the script:
```bash
python network_security_logger.py
```

3. Follow the prompts:
   - **Enter network interface**: Specify the network interface to monitor (e.g., `eth0`, `wlan0`).
   - **Enter filename to export logs**: Provide the filename (e.g., `output.json`).

## Example Workflow

### Input:
```bash
Enter network interface to monitor (e.g., 'eth0', 'wlan0'): wlan0
Enter filename to export logs as JSON (e.g., 'output.json'): logs.json
```

### Output:
- The logs are saved in a file named `logs.json` with structured JSON data capturing network traffic and any suspicious patterns detected.

## Future Enhancements

- Add support for monitoring other protocols (e.g., FTP, SSH, DNS).
- Include real-time alerts for critical patterns using notifications or emails.
- Integrate with databases for long-term log storage and analysis.
- Add an interactive GUI for non-technical users.

## Contribution Guidelines

Feel free to fork the repository and submit pull requests for any improvements or new features. Ensure that your contributions are well-documented and adhere to the project coding style.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
