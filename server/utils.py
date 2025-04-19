import re
import os
import requests
import time
import threading
from .config import config
from typing import Optional
from sqlalchemy.orm import Session

OUI_DATA = {}
oui_data_lock = threading.Lock()
last_oui_update_time = 0

def _parse_oui_line(line):
    match = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)', line)
    if match:
        prefix = match.group(1).replace('-', '').upper()
        vendor = match.group(2).strip()
        if len(prefix) == 6 and vendor:
            return prefix, vendor
    return None, None

def _load_oui_from_file(filepath):
    print(f"Loading OUI data from {filepath}...")
    data = {}
    loaded_count = 0
    skipped_count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                prefix, vendor = _parse_oui_line(line)
                if prefix:
                    if prefix not in data:
                        data[prefix] = vendor
                        loaded_count += 1
                elif line.strip() and '\t' in line and '(hex)' not in line:
                     skipped_count += 1

        print(f"Successfully loaded {loaded_count} unique OUI entries.")
        if skipped_count > 0:
            print(f"Skipped approximately {skipped_count} non-entry or malformed lines.")
        return data
    except FileNotFoundError:
        print(f"Error: OUI file not found at {filepath}.")
        return None
    except Exception as e:
        print(f"Error reading or parsing OUI file {filepath}: {e}")
        return None

def download_oui_file(url: str, filepath=config.OUI_LOCAL_FILE):
    print(f"Attempting to download OUI file from {url} to {filepath}...")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, stream=True, timeout=60, headers=headers)
        response.raise_for_status()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"OUI file downloaded successfully to {filepath}.")
        return True
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred during OUI download: {http_err}")
        try:
            print(f"Response Content (first 500 chars): {response.text[:500]}")
        except Exception: pass
        return False
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        return False
    except requests.exceptions.Timeout as timeout_err:
        print(f"Request timed out: {timeout_err}")
        return False
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred during the request: {req_err}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during OUI download: {e}")
        return False

def update_oui_data(force_download=False, db: Optional[Session] = None):
    global OUI_DATA, last_oui_update_time
    overall_success = False

    url_to_download = config.OUI_FILE_URL
    if db:
        try:
            from .core import get_all_settings
            settings = get_all_settings(db)
            db_url = settings.get('ouiFileUrl')
            if db_url:
                url_to_download = db_url
                print(f"Using OUI URL from DB settings: {url_to_download}")
            else:
                print("OUI URL setting is empty in DB, using default from config.")
        except Exception as e:
            print(f"Warning: Could not read OUI URL setting from DB: {e}. Using default from config.")
    else:
        print("DB session not provided to update_oui_data, using default OUI URL from config.")

    should_download = force_download
    if not os.path.exists(config.OUI_LOCAL_FILE):
        print("Local OUI file not found. Download required.")
        should_download = True

    download_attempted = False
    download_successful = False
    if should_download:
        download_attempted = True
        if force_download:
             print(f"Manual update triggered download attempt using URL: {url_to_download}")
        download_successful = download_oui_file(url=url_to_download, filepath=config.OUI_LOCAL_FILE)
        if not download_successful:
            print("Failed to download OUI file. Attempting to use existing local file if available.")

    loaded_data = _load_oui_from_file(config.OUI_LOCAL_FILE)
    if loaded_data:
        with oui_data_lock:
            OUI_DATA = loaded_data
            try:
                last_oui_update_time = os.path.getmtime(config.OUI_LOCAL_FILE)
            except OSError:
                 last_oui_update_time = time.time()
        print("Successfully loaded OUI data into memory.")
        if download_attempted:
            overall_success = download_successful
        else:
            overall_success = True
    else:
        print("Failed to load OUI data into memory.")
        if not OUI_DATA:
             print("Critical Warning: OUI data is empty. MAC address vendor lookups will fail.")
        else:
             print("Warning: Using potentially outdated OUI data from previous run.")
        overall_success = False
    return overall_success

def get_vendor_by_mac(mac_address):
    if not OUI_DATA and last_oui_update_time == 0:
        print("OUI data not loaded, attempting initial load/update...")
        update_oui_data()

    if not mac_address:
        return "Unknown"

    try:
        normalized_mac = re.sub(r'[^0-9A-Fa-f]', '', str(mac_address)).upper()
        if len(normalized_mac) >= 6:
            prefix = normalized_mac[:6]
            with oui_data_lock:
                vendor = OUI_DATA.get(prefix, "Unknown")
            return vendor
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error during OUI lookup for MAC '{mac_address}': {e}")
        return "Unknown"

def get_oui_status():
    with oui_data_lock:
        count = len(OUI_DATA)
    update_time_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(last_oui_update_time)) if last_oui_update_time else "Never loaded"
    file_exists = os.path.exists(config.OUI_LOCAL_FILE)
    file_mod_time_str = "N/A"
    if file_exists:
        try:
            file_mod_time = os.path.getmtime(config.OUI_LOCAL_FILE)
            file_mod_time_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(file_mod_time))
        except OSError:
            file_mod_time_str = "Error reading time"

    return {
        "entries_in_memory": count,
        "last_memory_load_time": update_time_str,
        "local_file_path": config.OUI_LOCAL_FILE,
        "local_file_exists": file_exists,
        "local_file_last_modified": file_mod_time_str
    }
