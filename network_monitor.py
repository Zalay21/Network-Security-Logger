import os
import logging
import socket
import datetime
import pyshark
import json

# Setting up logging
logging.basicConfig(
    filename='network_security_logger.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Utility function to get local IP
def get_local_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

# Logger class
class NetworkSecurityLogger:
    def __init__(self):
        self.local_ip = get_local_ip()
        self.suspicious_patterns = ["password", "credit card", "ssn"]
        self.packet_limit = 100  # Stop after capturing these many packets

    def log_system_info(self):
        """Log system and network information."""
        info = {
            "hostname": socket.gethostname(),
            "local_ip": self.local_ip,
            "date": datetime.datetime.now().isoformat(),
            "os": os.name
        }
        logging.info("System Info: %s", json.dumps(info))

    def monitor_traffic(self, interface):
        """Monitor network traffic and log suspicious activity."""
        logging.info(f"Starting packet capture on interface {interface}")
        capture = pyshark.LiveCapture(interface=interface)

        try:
            for packet in capture.sniff_continuously(packet_count=self.packet_limit):
                self.analyze_packet(packet)
        except KeyboardInterrupt:
            logging.warning("Packet monitoring stopped by user.")
        except Exception as e:
            logging.error("Error during packet capture: %s", str(e))

    def analyze_packet(self, packet):
        """Analyze captured packets for suspicious patterns."""
        try:
            if hasattr(packet, 'http'):  # Only analyze HTTP traffic for simplicity
                http_payload = packet.http.get('file_data', '')
                for pattern in self.suspicious_patterns:
                    if pattern in http_payload.lower():
                        logging.warning(
                            f"Suspicious pattern detected: {pattern} in packet: {http_payload}"
                        )

                logging.info(f"HTTP Packet captured: {http_payload}")
        except Exception as e:
            logging.error("Error analyzing packet: %s", str(e))

    def export_logs_as_json(self, output_file):
        """Export log file to a JSON file for better visibility."""
        try:
            with open('network_security_logger.log', 'r') as log_file:
                logs = log_file.readlines()

            logs_as_json = [
                {"timestamp": log.split(' - ')[0], "level": log.split(' - ')[1], "message": log.split(' - ')[2].strip()}
                for log in logs
            ]

            with open(output_file, 'w') as json_file:
                json.dump(logs_as_json, json_file, indent=4)
            logging.info(f"Logs exported to {output_file}")
        except Exception as e:
            logging.error("Error exporting logs to JSON: %s", str(e))

# Main functionality
if __name__ == "__main__":
    logger = NetworkSecurityLogger()
    logger.log_system_info()

    interface = input("Enter network interface to monitor (e.g., 'eth0', 'wlan0'): ")
    logger.monitor_traffic(interface)

    export_file = input("Enter filename to export logs as JSON (e.g., 'output.json'): ")
    logger.export_logs_as_json(export_file)
    print("Network monitoring completed and logs exported.")
