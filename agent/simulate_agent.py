import requests
import json
import datetime
import random
import time
import sys

SERVER_URL = "http://127.0.0.1:8000/api/agent/report"
AGENT_ID = "sim_agent_002"
AGENT_NAME = "Simulated Agent #1"
REPORT_INTERVAL = 15

AGENT_API_KEY = sys.argv[1] if len(sys.argv) > 1 else "PLACEHOLDER_API_KEY"
if AGENT_API_KEY == "PLACEHOLDER_API_KEY":
    print("Warning: API Key not provided via command line.")
    print("         Using a placeholder. This will likely fail authentication.")
    print("Usage: python simulate_agent.py <your_actual_api_key>")

STABLE_DEVICES = [
    {"ip": "192.168.1.1", "mac": "00:50:56:A1:B2:C3"},
    {"ip": "192.168.1.10", "mac": "08:00:27:D4:E5:F6"},
    {"ip": "192.168.1.50", "mac": "AA:BB:CC:11:22:33"},
    {"ip": "192.168.1.250", "mac": "F8:FE:5E:70:7E:11"},
    {"ip": "192.168.1.149", "mac": "94:D3:31:F1:82:DF"},
]
TRANSIENT_DEVICES_POOL = [
    (50, "192.168.1.101", "11:22:33:AA:BB:CC"),
    (30, "192.168.1.102", "DD:EE:FF:44:55:66"),
    (70, "192.168.1.254", "00:11:22:33:44:55"),
]

def generate_device_list():
    current_devices = list(STABLE_DEVICES)
    for chance, ip, mac in TRANSIENT_DEVICES_POOL:
        if random.randint(1, 100) <= chance:
            current_devices.append({"ip": ip, "mac": mac})
    return current_devices

def send_report(agent_id, devices, api_key):
    report_data = {
        "agent_id": agent_id,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "discovered_devices": devices,
        "agent_name": AGENT_NAME,
        "ip_address": "192.168.1.2"
    }

    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': api_key
    }

    try:
        print(f"Sending report for agent {agent_id} (API Key: ...{api_key[-4:]}), {len(devices)} devices")
        response = requests.post(SERVER_URL, headers=headers, data=json.dumps(report_data), timeout=10)
        response.raise_for_status()
        print(f"Report sent successfully. Status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to server at {SERVER_URL}.")
    except requests.exceptions.Timeout:
        print(f"Error: Request timed out.")
    except requests.exceptions.HTTPError as e:
         print(f"Error: HTTP Error sending report: {e}")
         if e.response is not None:
            print(f"Server Status Code: {e.response.status_code}")
            print(f"Server Response: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending report: {e}")


if __name__ == "__main__":
    print(f"--- Starting Agent Simulator (ID: {AGENT_ID}) ---")
    print(f"Server: {SERVER_URL}")
    print(f"Interval: {REPORT_INTERVAL} seconds")
    if AGENT_API_KEY != "PLACEHOLDER_API_KEY":
        print(f"API Key: ...{AGENT_API_KEY[-4:]}")

    print("Press Ctrl+C to stop.")

    try:
        while True:
            devices_to_report = generate_device_list()
            send_report(AGENT_ID, devices_to_report, AGENT_API_KEY)
            time.sleep(REPORT_INTERVAL)
    except KeyboardInterrupt:
        print("\n--- Agent Simulator Stopped ---")
