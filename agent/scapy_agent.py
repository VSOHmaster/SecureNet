import requests
import json
import datetime
import time
import sys
import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        from scapy.all import Ether, ARP, srp
        SCAPY_AVAILABLE = True
    except ImportError:
        print("Error: Scapy library not found. Please install it: pip install scapy")
        SCAPY_AVAILABLE = False
        sys.exit(1)
    except OSError as e:
         print(f"Error importing Scapy (potential permission issue?): {e}")
         print("Scapy might require root/administrator privileges.")
         print("Try running with 'sudo python scapy_agent.py ...'")
         SCAPY_AVAILABLE = False
         sys.exit(1)

AGENT_ID = "scapy_agent_001"
AGENT_NAME = "Scapy Network Scanner Agent"
DEFAULT_AGENT_CONFIG = {
    "scan_interval": 60,
    "scan_timeout": 5,
    "network_cidr": "192.168.1.0/24"
}
API_REPORT_ENDPOINT = "/api/agent/report"
API_CONFIG_ENDPOINT = "/api/agent/config"

if len(sys.argv) < 3:
    print("Error: API Key and Server URL not provided.")
    print("Usage: python scapy_agent.py <your_api_key> <base_server_url> [network_cidr]")
    print("Example: python scapy_agent.py abcdef12345 'http://192.168.1.100:8000' '192.168.1.0/24'")
    sys.exit(1)

AGENT_API_KEY = sys.argv[1]
BASE_SERVER_URL = sys.argv[2].rstrip('/')

SERVER_URL = BASE_SERVER_URL + API_REPORT_ENDPOINT
CONFIG_SERVER_URL = BASE_SERVER_URL + API_CONFIG_ENDPOINT

if not BASE_SERVER_URL.startswith(('http://', 'https://')):
    print(f"Warning: Server URL '{BASE_SERVER_URL}' does not look like a valid HTTP/HTTPS URL.")

def is_admin():
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        elif os.name == 'posix':
            return os.geteuid() == 0
        else:
             return False
    except Exception:
        return False

if SCAPY_AVAILABLE and not is_admin():
     print("Warning: Script not running with root/administrator privileges.")
     print("         Network scanning might fail due to permissions.")

def get_configuration(server_url: str, api_key: str) -> dict:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Requesting configuration from {server_url}...")
    headers = {'X-API-Key': api_key}
    try:
        response = requests.get(server_url, headers=headers, timeout=10)
        response.raise_for_status()
        config_data = response.json()
        if all(k in config_data for k in ["scan_interval", "scan_timeout", "network_cidr"]):
             print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Configuration received: {config_data}")
             config_data['scan_interval'] = int(config_data['scan_interval'])
             config_data['scan_timeout'] = int(config_data['scan_timeout'])
             return config_data
        else:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error: Received incomplete configuration data.")
            return DEFAULT_AGENT_CONFIG
    except requests.exceptions.ConnectionError:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error: Could not connect to server at {server_url} for config.")
    except requests.exceptions.Timeout:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error: Request timed out getting config from {server_url}.")
    except requests.exceptions.HTTPError as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error: HTTP Error getting config: {e.response.status_code}")
        if e.response.status_code == 404:
            print("       Reason: Agent not found or invalid API key.")
        elif e.response.status_code == 401:
             print("       Reason: Missing API Key header (client error).")
        else:
             try:
                 print(f"       Server Response: {e.response.text}")
             except Exception: pass
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error getting or parsing configuration: {e}")
    except Exception as e:
         print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Unexpected error during configuration fetch: {e}")

    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Using default configuration.")
    return DEFAULT_AGENT_CONFIG 

def discover_devices_scapy(network_cidr, timeout):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Starting ARP scan (round 1) on {network_cidr} with timeout {timeout}s...")
    all_discovered_devices = {}

    scan_attempts = 2
    scan_delay = 2

    for attempt in range(1, scan_attempts + 1):
        discovered_in_attempt = 0
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr)
            answered, unanswered = srp(arp_request, timeout=timeout, verbose=False, retry=-2)

            for sent, received in answered:
                mac = received.hwsrc.upper()
                ip = received.psrc
                if mac not in all_discovered_devices:
                     discovered_in_attempt += 1
                all_discovered_devices[mac] = ip

            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Scan round {attempt} complete. Found {len(answered)} responses ({discovered_in_attempt} new MACs).")

        except OSError as e:
             print(f"Error during Scapy scan round {attempt}: {e}. Ensure script has privileges.")
             if "Operation not permitted" in str(e) or "permission denied" in str(e).lower():
                 print("Aborting further scan attempts due to permission error.")
                 break
        except Exception as e:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] An unexpected error occurred during Scapy scan round {attempt}: {e}")

        if attempt < scan_attempts:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Waiting {scan_delay}s before next scan round...")
            time.sleep(scan_delay)
    
    final_device_list = [{"mac": mac, "ip": ip} for mac, ip in all_discovered_devices.items()]
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Total unique devices found after {scan_attempts} rounds: {len(final_device_list)}")
    return final_device_list

def get_agent_ip():
    agent_ip_address = "?.?.?.?"
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('10.254.254.254', 1))
            agent_ip_address = s.getsockname()[0]
        except Exception:
             agent_ip_address = '127.0.0.1'
        finally:
            s.close()
    except Exception:
        pass
    return agent_ip_address

def send_report(agent_id, agent_name, devices, api_key, server_url):
    agent_ip_address = get_agent_ip()

    report_data = {
        "agent_id": agent_id,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "discovered_devices": devices,
        "agent_name": agent_name,
        "ip_address": agent_ip_address
    }

    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': api_key
    }

    try:
        print(f"Sending report for agent {agent_id} ({len(devices)} devices) to {server_url}")
        response = requests.post(server_url, headers=headers, data=json.dumps(report_data), timeout=15)
        response.raise_for_status()
        print(f"Report sent successfully. Status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to server at {server_url}.")
    except requests.exceptions.Timeout:
        print(f"Error: Request timed out connecting to {server_url}.")
    except requests.exceptions.HTTPError as e:
         print(f"Error: HTTP Error sending report: {e}")
         if e.response is not None:
            print(f"Server Status Code: {e.response.status_code}")
            print(f"Server Response: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending report: {e}")

if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
         sys.exit(1)

    print(f"--- Starting Scapy Agent (ID: {AGENT_ID}) ---")
    print(f"Server: {SERVER_URL}")
    print(f"Config Endpoint: {CONFIG_SERVER_URL}")
    print(f"API Key: ...{AGENT_API_KEY[-4:]}")

    current_config = get_configuration(CONFIG_SERVER_URL, AGENT_API_KEY)
    if not current_config.get("network_cidr"):
         fallback_cidr = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_AGENT_CONFIG["network_cidr"]
         print(f"Warning: Server did not provide CIDR, using fallback: {fallback_cidr}")
         current_config["network_cidr"] = fallback_cidr

    last_config_check_time = time.time()
    config_check_interval = 30

    print(f"Initial config: Interval={current_config['scan_interval']}s, Timeout={current_config['scan_timeout']}s, Network={current_config['network_cidr']}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            current_time = time.time()
            if current_time - last_config_check_time > config_check_interval:
                print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Checking for updated configuration...")
                new_config = get_configuration(CONFIG_SERVER_URL, AGENT_API_KEY)
                if all(k in new_config for k in DEFAULT_AGENT_CONFIG.keys()):
                    if new_config != current_config:
                        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Configuration updated: {new_config}")
                        current_config = new_config
                    else:
                        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Configuration hasn't changed.")
                last_config_check_time = current_time
                print("")

            devices_to_report = discover_devices_scapy(
                network_cidr=current_config['network_cidr'],
                timeout=current_config['scan_timeout']
            )

            if devices_to_report:
                 send_report(AGENT_ID, AGENT_NAME, devices_to_report, AGENT_API_KEY, SERVER_URL)
            else:
                 print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] No devices discovered in this scan cycle.")

            wait_interval = current_config['scan_interval']
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Waiting for {wait_interval} seconds...")
            time.sleep(wait_interval)

    except KeyboardInterrupt:
        print("\n--- Scapy Agent Stopped ---")
    except Exception as e:
        print(f"\nAn unexpected error occurred in the main loop: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
