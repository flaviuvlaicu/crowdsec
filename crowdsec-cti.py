#!/usr/bin/env python3
import requests
import time
import re
import logging
import os
from datetime import datetime
import ipaddress
import subprocess
import threading
import signal
import sys
try:
    from cachetools import TTLCache
except ImportError:
    print("Error: 'cachetools' module not found. Install it with 'pip3 install cachetools'.")
    exit(1)

# Custom filter to only allow DEBUG-level messages
class DebugFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.DEBUG

# Configure logging
try:
    # Main logger configuration for INFO and above
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/crowdsec/crowdsec_cti.log'),
            logging.StreamHandler()
        ]
    )
    # Add separate handler for DEBUG messages
    debug_handler = logging.FileHandler('/var/log/crowdsec/crowdsec_cti_debug.log')
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.addFilter(DebugFilter())
    debug_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger('').addHandler(debug_handler)
except PermissionError:
    print("Error: Cannot write to log files. Check permissions for /var/log/crowdsec/crowdsec_cti.log and /var/log/crowdsec/crowdsec_cti_debug.log.")
    exit(1)

# Signal handler for stop/reload
def signal_handler(sig, frame):
    if sig == signal.SIGTERM:
        logging.debug("Stopping crowdsec_cti")
        logging.debug("crowdsec_cti stopped")
        sys.exit(0)
    elif sig == signal.SIGHUP:
        logging.debug("Reloading crowdsec_cti")
        # No reload logic implemented; just log and continue
        return

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

# CrowdSec CTI API configuration
API_KEY = os.getenv("CROWDSEC_API_KEY", "YOUR API HERE")
if not API_KEY:
    logging.error("API key not found in environment variable CROWDSEC_API_KEY")
    exit(1)
API_URL = "https://cti.api.crowdsec.net/v2/smoke/{}"
HEADERS = {"x-api-key": API_KEY}

# File paths
FAST_LOG = "/var/log/suricata/fast.log"
FILTERED_LOG = "/var/log/suricata/filtered-fast.log"

# IP address regex for extracting IPs from fast.log
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Classifications to include in filtered log
MALICIOUS_CLASSIFICATIONS = {"Malicious", "Suspicious", "Benign"}

# Classifications to exclude
CLEAN_CLASSIFICATIONS = {"Known", "Safe", "Unknown"}

# String to identify Nmap alerts
NMAP_PATTERN = r'nmap'

# Private IP ranges
PRIVATE_IP_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16")
]

# Cache for CTI results (IP -> (classification, behaviors)) with 1-hour TTL
CTI_CACHE = TTLCache(maxsize=1000, ttl=3600)  # 1 hour in seconds

# Global variable to store the current public IP
CURRENT_PUBLIC_IP = None
PUBLIC_IP_LOCK = threading.Lock()

def get_public_ip(interface="pppoe1"):
    """Retrieve the public IP address from the specified network interface."""
    try:
        result = subprocess.run(['ifconfig', interface], capture_output=True, text=True, check=True)
        output = result.stdout
        ip_match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
        if ip_match:
            ip = ip_match.group(1)
            return ip
        else:
            logging.warning(f"No public IP found in ifconfig output for {interface}")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run ifconfig for {interface}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error retrieving public IP: {e}")
        return None

def update_public_ip_periodically(interface="pppoe1", interval=300):
    """Periodically update the public IP address in a background thread."""
    global CURRENT_PUBLIC_IP
    while True:
        new_ip = get_public_ip(interface)
        with PUBLIC_IP_LOCK:
            if new_ip != CURRENT_PUBLIC_IP:
                CURRENT_PUBLIC_IP = new_ip
        time.sleep(interval)

def is_private_ip(ip):
    """Check if an IP is in a private range."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return any(ip_addr in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        logging.error(f"Invalid IP address format: {ip}")
        return False

def query_crowdsec_cti(ip):
    """Query CrowdSec CTI API for IP reputation and behaviors, using cache."""
    cached = CTI_CACHE.get(ip)
    if cached and cached[0] is not None:
        classification, behaviors = cached
        logging.info(f"Cache for {ip} ({classification})")
        return classification, behaviors, "cache"

    for attempt in range(3):
        try:
            response = requests.get(API_URL.format(ip), headers=HEADERS, timeout=5)
            if response.status_code == 200:
                data = response.json()
                behaviors = data.get("behaviors", [])
                behavior_labels = {b.get("label", "Unknown").capitalize() for b in behaviors}
                reputation = data.get("reputation", "Unknown").capitalize()

                if reputation != "Known":
                    logging.debug(f"IP {ip} behaviors: {behavior_labels}, reputation: {reputation}")

                classification = reputation
                if MALICIOUS_CLASSIFICATIONS & behavior_labels:
                    classification = max(MALICIOUS_CLASSIFICATIONS & behavior_labels, default=reputation)

                behavior_names = [b.get("name", "Unknown") for b in behaviors] if classification in MALICIOUS_CLASSIFICATIONS else []

                CTI_CACHE[ip] = (classification, behavior_names)
                if classification != "Known":
                    logging.debug(f"Cached IP {ip}: {classification}, behaviors: {behavior_names}")
                logging.info(f"Query for {ip} ({classification})")
                return classification, behavior_names, "query"
            elif response.status_code == 429:
                logging.warning(f"Rate limit exceeded. Retrying in {60 * (2 ** attempt)}s...")
                time.sleep(60 * (2 ** attempt))
                continue
            elif response.status_code == 404:
                CTI_CACHE[ip] = ("Unknown", [])
                logging.info(f"Query for {ip} (Unknown)")
                return "Unknown", [], "query"
            else:
                logging.error(f"API error for IP {ip}: {response.status_code} - {response.text}")
                CTI_CACHE[ip] = ("Unknown", [])
                logging.info(f"Query for {ip} (Unknown)")
                return "Unknown", [], "query"
        except requests.RequestException as e:
            logging.error(f"Failed to query CTI for IP {ip}: {e}")
            CTI_CACHE[ip] = ("Unknown", [])
            logging.info(f"Query for {ip} (Unknown)")
            return "Unknown", [], "query"
    logging.error(f"Max retries exceeded for IP {ip}")
    CTI_CACHE[ip] = ("Unknown", [])
    logging.info(f"Query for {ip} (Unknown)")
    return "Unknown", [], "query"

def process_log_line(line):
    """Process a single log line from fast.log."""
    if not line.strip():
        return

    if re.search(NMAP_PATTERN, line, re.IGNORECASE):
        logging.debug(f"Skipping Nmap-related alert: {line.strip()}")
        return

    ips = re.findall(IP_REGEX, line)
    if not ips:
        logging.warning(f"No IPs found in line: {line.strip()}")
        return

    with PUBLIC_IP_LOCK:
        current_public_ip = CURRENT_PUBLIC_IP

    for ip in set(ips):
        if ip == current_public_ip:
            continue
        if is_private_ip(ip):
            logging.debug(f"Skipping private IP: {ip}")
            continue
        classification, behaviors, source = query_crowdsec_cti(ip)
        if classification in MALICIOUS_CLASSIFICATIONS:
            try:
                with open(FILTERED_LOG, 'a') as f:
                    f.write(f"{line.strip()} [CrowdSec CTI: {classification}]\n")
                logging.info(f"Added [{source}] to filtered-fast.log: IP {ip} ({classification}, Behaviors: {behaviors}) - {line.strip()}")
            except PermissionError:
                logging.error(f"Cannot write to {FILTERED_LOG}. Check permissions.")
        elif classification in CLEAN_CLASSIFICATIONS:
            logging.debug(f"Skipping clean IP {ip} with classification {classification}")
        else:
            logging.warning(f"Unknown classification {classification} for IP {ip}")

def tail_file(file_path):
    """Tail a file and yield new lines, handling file rotation and deletion."""
    while True:
        try:
            with open(file_path, 'r') as f:
                # Get initial inode to detect rotation
                initial_stat = os.fstat(f.fileno())
                initial_inode = initial_stat.st_ino
                f.seek(0, os.SEEK_END)
                logging.debug(f"Opened {file_path} (inode: {initial_inode})")

                while True:
                    line = f.readline()
                    if line:
                        yield line
                    else:
                        # Check for file rotation by comparing inode
                        try:
                            current_stat = os.stat(file_path)
                            if current_stat.st_ino != initial_inode:
                                logging.debug(f"File {file_path} rotated (new inode: {current_stat.st_ino})")
                                break  # Break to reopen the file
                        except FileNotFoundError:
                            logging.warning(f"File {file_path} not found, retrying in 5 seconds...")
                            break  # Break to retry opening
                        time.sleep(0.1)  # Short sleep to avoid CPU overuse
        except FileNotFoundError:
            logging.warning(f"File {file_path} not found, retrying in 5 seconds...")
            time.sleep(5)  # Wait before retrying
        except PermissionError:
            logging.error(f"Cannot read {file_path}. Check permissions.")
            exit(1)
        except OSError as e:
            logging.error(f"Error accessing {file_path}: {e}. Retrying in 5 seconds...")
            time.sleep(5)  # Handle other OS errors (e.g., file temporarily inaccessible)

def ensure_log_files():
    """Ensure log files exist and are writable."""
    for log_file in [FAST_LOG, FILTERED_LOG, '/var/log/crowdsec/crowdsec_cti.log', '/var/log/crowdsec/crowdsec_cti_debug.log']:
        log_dir = os.path.dirname(log_file)
        try:
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                logging.debug(f"Created directory {log_dir}")
            if not os.path.exists(log_file):
                with open(log_file, 'a'):
                    os.utime(log_file, None)
                logging.debug(f"Created empty log file {log_file}")
        except PermissionError:
            logging.error(f"Cannot create {log_file} or its directory. Check permissions.")
            exit(1)

def main():
    """Main function to monitor fast.log and filter alerts."""
    logging.debug("Starting CrowdSec-Suricata integration script on OPNsense")
    try:
        # Initialize public IP
        global CURRENT_PUBLIC_IP
        with PUBLIC_IP_LOCK:
            CURRENT_PUBLIC_IP = get_public_ip()
        if not CURRENT_PUBLIC_IP:
            logging.error("Could not retrieve initial public IP. Continuing without public IP filtering.")

        # Start background thread to update public IP
        ip_update_thread = threading.Thread(target=update_public_ip_periodically, daemon=True)
        ip_update_thread.start()

        ensure_log_files()
        logging.debug(f"Monitoring {FAST_LOG} for new alerts")
        for line in tail_file(FAST_LOG):
            process_log_line(line)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.debug("Script terminated by user")
        exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        exit(1)
