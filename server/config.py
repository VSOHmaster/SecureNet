import os
from dotenv import load_dotenv
import datetime

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    print(f"Warning: .env file not found at {dotenv_path}. Using defaults or environment variables.")

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL environment variable is not set. Application cannot start.")

    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
         print("\n" + "="*60)
         print("WARNING: SECRET_KEY environment variable not set!")
         print("Using a default, insecure key. PLEASE SET a strong, random")
         print("SECRET_KEY in your .env file or environment for production.")
         print("Generate one using: python -c 'import secrets; print(secrets.token_hex(32))'")
         print("="*60 + "\n")
         SECRET_KEY = 'default-insecure-fallback-secret-key-CHANGE-ME'

    DEVICE_ACTIVITY_TIMEOUT_MINUTES_STR = os.environ.get('DEVICE_ACTIVITY_TIMEOUT_MINUTES', '60')
    try:
        DEVICE_ACTIVITY_TIMEOUT_MINUTES = int(DEVICE_ACTIVITY_TIMEOUT_MINUTES_STR)
        if DEVICE_ACTIVITY_TIMEOUT_MINUTES <= 0:
            print(f"Warning: Invalid DEVICE_ACTIVITY_TIMEOUT_MINUTES '{DEVICE_ACTIVITY_TIMEOUT_MINUTES_STR}'. Using default 60.")
            DEVICE_ACTIVITY_TIMEOUT_MINUTES = 60
    except ValueError:
        print(f"Warning: Invalid format for DEVICE_ACTIVITY_TIMEOUT_MINUTES '{DEVICE_ACTIVITY_TIMEOUT_MINUTES_STR}'. Using default 60.")
        DEVICE_ACTIVITY_TIMEOUT_MINUTES = 60

    OUI_FILE_URL = os.environ.get("OUI_FILE_URL", "https://standards-oui.ieee.org/oui/oui.txt")
    DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
    OUI_LOCAL_FILE = os.path.join(DATA_DIR, 'oui.txt')

    if not os.path.exists(DATA_DIR):
        try:
            os.makedirs(DATA_DIR)
        except OSError as e:
            print(f"Error creating data directory {DATA_DIR}: {e}")

config = Config()
