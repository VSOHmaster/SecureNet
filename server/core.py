import datetime
import json
import requests
from sqlalchemy.orm import Session
from sqlalchemy import desc, update, func, and_, or_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from typing import Union

from . import models
from .config import config
from datetime import timezone, timedelta
from .utils import get_vendor_by_mac, update_oui_data
from .database import SessionLocal

SEVERITY_LEVELS = {
    "Info": 1,
    "Warning": 2,
    "High": 3,
    "Critical": 4
}

def verify_agent_api_key(api_key: str, db: Session) -> Union[models.Agent, None]:
    if not api_key:
        return None
    agent = db.query(models.Agent).filter_by(api_key=api_key).first()
    return agent

def process_agent_report(agent_data: dict, api_key: str, db: Session):
    agent = verify_agent_api_key(api_key, db)
    if not agent:
        print(f"Error: Invalid or missing API key received.")
        return {"status": "error", "message": "Invalid or missing API key"}, 401

    current_status_before_update = agent.status

    agent_ext_id = agent.agent_ext_id
    discovered_devices_data = agent_data.get("discovered_devices", [])
    timestamp_str = agent_data.get("timestamp")

    try:
        report_time = datetime.datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')) \
            if isinstance(timestamp_str, str) else datetime.datetime.utcnow()
    except (ValueError, TypeError):
        report_time = datetime.datetime.utcnow()

    current_time = datetime.datetime.utcnow()

    agent.status = 'active'
    agent.last_seen = current_time
    agent.ip_address = agent_data.get('ip_address', agent.ip_address)

    if current_status_before_update == 'inactive':
        create_alert(
            db=db,
            message=f"Агент '{agent.name}' ({agent.ip_address or 'IP не указан'}) снова активен.",
            severity="Info", # Изменено на Info
            badge_color="success"
        )

    processed_macs = set()

    try:
        activity_threshold_time = get_device_activity_threshold_time(db)
    except Exception:
        activity_threshold_time = current_time - datetime.timedelta(minutes=config.DEVICE_ACTIVITY_TIMEOUT_MINUTES)
    
    if isinstance(discovered_devices_data, list):
        for device_info in discovered_devices_data:
            mac = device_info.get("mac")
            ip = device_info.get("ip")

            if not mac or not ip: continue
            mac = mac.upper()
            processed_macs.add(mac)

            device = db.query(models.Device).filter_by(mac_address=mac).first()

            if device:
                was_considered_inactive = not device.is_considered_active

                device.last_seen = current_time
                device.is_considered_active = True
                if device.ip_address != ip:
                    print(f"Device {mac} changed IP from {device.ip_address} to {ip}")
                    device.ip_address = ip
                
                if was_considered_inactive:
                    if device.status == 'trusted':
                        alert_severity = "Info"
                        alert_badge_color = "success"
                        alert_message = (f"Снова обнаружено доверенное устройство:\n"
                                         f"IP={ip}, MAC={mac}\n"
                                         f"Производитель: {device.vendor or 'Неизвестен'}\n"
                                         f"Имя/Заметка: {device.notes or '(нет)'}")
                    elif device.status == 'untrusted':
                        alert_severity = "Warning"
                        alert_badge_color = "warning"
                        alert_message = (f"Снова обнаружено недоверенное устройство:\n"
                                         f"IP={ip}, MAC={mac}\n"
                                         f"Производитель: {device.vendor or 'Неизвестен'}\n"
                                         f"Имя/Заметка: {device.notes or '(нет)'}")
                    else:
                        alert_severity = "Critical"
                        alert_badge_color = "danger"
                        alert_message = (f"Снова обнаружено ЗАБЛОКИРОВАННОЕ устройство:\n"
                                         f"IP={ip}, MAC={mac}\n"
                                         f"Производитель: {device.vendor or 'Неизвестен'}\n"
                                         f"Имя/Заметка: {device.notes or '(нет)'}")
                    create_alert(db, alert_message, alert_severity, alert_badge_color)
                elif device.status == 'blocked':
                     create_alert(
                         db=db,
                         message=(f"Обнаружено ЗАБЛОКИРОВАННОЕ устройство (продолжает быть активным):\n"
                                  f"IP={ip}, MAC={mac}\n"
                                  f"Имя/Заметка: {device.notes or '(нет)'}"),
                         severity="Critical",
                         badge_color="danger"
                     )
                elif device.status == 'untrusted':
                     create_alert(
                         db=db,
                         message=(f"Обнаружено НЕДОВЕРЕННОЕ устройство (продолжает быть активным):\n"
                                     f"IP={ip}, MAC={mac}\n"
                                     f"Производитель: {device.vendor or 'Неизвестен'}\n"
                                     f"Имя/Заметка: {device.notes or '(нет)'}"),
                         severity="Warning",
                         badge_color="warning"
                     )

            else:
                vendor = get_vendor_by_mac(mac)
                new_device = models.Device(
                    mac_address=mac,
                    ip_address=ip,
                    vendor=vendor,
                    status='untrusted',
                    first_seen=current_time,
                    last_seen=current_time,
                    is_considered_active=True
                )
                db.add(new_device)

                alert_severity = "High"
                alert_badge_color = "warning"
                alert_message = (f"Обнаружено НОВОЕ устройство:\n"
                                 f"IP={ip}, MAC={mac}\n"
                                 f"Производитель: {vendor or 'Неизвестен'}")
                create_alert(db, alert_message, alert_severity, alert_badge_color)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error committing agent report data for {agent_ext_id}: {e}")
        return {"status": "error", "message": f"Ошибка БД при обработке отчета: {e}"}, 500

    return {"status": "success", "message": "Отчет обработан"}, 200

def send_telegram_notification(message: str, severity: str, db: Session):
    print(f"Attempting to send Telegram notification: '{message[:50]}...'")
    try:
        settings = get_all_settings(db)
        notify_method = settings.get('notifyMethod', 'None')
        bot_token = settings.get('botToken')

        chat_ids = settings.get('telegramUsers', [])
        threshold_str = settings.get('notificationSeverityThreshold', 'Warning')
        current_level = SEVERITY_LEVELS.get(severity, 0)
        threshold_level = SEVERITY_LEVELS.get(threshold_str, 2)

        if current_level < threshold_level:
             print(f"Skipping notification: Severity '{severity}' ({current_level}) is below threshold '{threshold_str}' ({threshold_level}).")
             return

        if notify_method != 'Telegram' or not bot_token:
            print(f"Telegram notifications disabled or Bot Token not set. Method: {notify_method}, Token set: {bool(bot_token)}")
            return
        
        if not isinstance(chat_ids, list) or not chat_ids:
            print("No valid Telegram Chat IDs configured or list is empty.")
            return
        
        telegram_api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        for chat_id in chat_ids:
            if not isinstance(chat_id, str) or not chat_id.strip():
                print(f"Skipping invalid chat_id entry: {chat_id}")
                continue

            chat_id_cleaned = chat_id.strip()

            payload = {
                'chat_id': chat_id_cleaned,
                'text': message,
                'parse_mode': 'HTML'
            }
            try:
                response = requests.post(telegram_api_url, data=payload, timeout=10)
                response_data = response.json()

                if response.status_code == 200 and response_data.get('ok'):
                    print(f"Successfully sent Telegram notification to chat_id: {chat_id_cleaned}")
                else:
                    error_msg = response_data.get('description', 'Unknown error')
                    print(f"Failed to send Telegram notification to chat_id: {chat_id_cleaned}. Status: {response.status_code}, Error: {error_msg}")

            except requests.exceptions.Timeout:
                 print(f"Error sending Telegram to {chat_id_cleaned}: Request timed out.")
            except requests.exceptions.RequestException as e:
                print(f"Error sending Telegram notification to chat_id {chat_id_cleaned}: {e}")

    except Exception as e:
        print(f"An unexpected error occurred in send_telegram_notification: {e}")
        import traceback
        traceback.print_exc()

def create_alert(db: Session, message: str, severity: str, badge_color: str, **kwargs):
    should_notify = True
    try:
        settings = get_all_settings(db)
        cooldown_cycles = settings.get('alertRepeatCooldown', 5)
        scan_interval_sec = settings.get('scanInterval', 60)

        scan_interval_sec = max(10, scan_interval_sec)

        if cooldown_cycles > 0:
            cooldown_seconds = cooldown_cycles * scan_interval_sec
            threshold_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=cooldown_seconds)

            last_similar_alert = db.query(models.Alert)\
                                   .filter(models.Alert.message == message)\
                                   .filter(models.Alert.timestamp >= threshold_time)\
                                   .order_by(desc(models.Alert.timestamp))\
                                   .first()

            if last_similar_alert:
                should_notify = False
                print(f"Notification skipped due to cooldown (found ID {last_similar_alert.id} from {last_similar_alert.timestamp}). Message: '{message[:50]}...'")

        if should_notify:
            alert = models.Alert(
                message=message,
                severity=severity,
                badge_color=badge_color,
                **kwargs
            )
            db.add(alert)
            try:
                 db.commit()
            except Exception as commit_err:
                 db.rollback()
                 print(f"Error saving alert: {commit_err}")
                 return

            send_telegram_notification(
                 message=f"🚨 SecureNet Оповещение ({severity}):\n{message}",
                 severity=severity,
                 db=db
            )
        else:
             pass

    except Exception as e:
        db.rollback()
        print(f"Error while creating/checking cooldown/preparing notification: {e}")
        import traceback
        traceback.print_exc()

def get_all_settings(db: Session) -> dict:
    settings_list = db.query(models.Setting).all()
    settings_dict = {setting.key: setting.value for setting in settings_list}
    defaults = {
        'scanInterval': '60', 'scanTimeout': '5',
        'ouiFileUrl': config.OUI_FILE_URL,
        'defaultNetworkCidr': '192.168.1.0/24',
        'maxConnections': '100',
        'responseTimeout': '300',
        'notifyMethod': 'Telegram', 'notificationSeverityThreshold': 'Warning',
        'alertRepeatCooldown': '5',
        'botToken': '', 'telegramUsers': '[]',
        'smtpServer': '', 'smtpPort': '465', 'emailSender': '', 'emailPassword': '',
        'emailRecipient': '',
        'deviceActivityTimeout': str(config.DEVICE_ACTIVITY_TIMEOUT_MINUTES),
        'analyticsCollectionIntervalSeconds': '300'
    }
    for key, default_value in defaults.items():
        settings_dict.setdefault(key, default_value)

    numbers = ['scanInterval', 'scanTimeout',
               'maxConnections', 'responseTimeout',
               'alertRepeatCooldown', 'smtpPort', 'deviceActivityTimeout',
               'analyticsCollectionIntervalSeconds']
    for key in numbers:
        try:
            settings_dict[key] = int(settings_dict[key])
        except (ValueError, TypeError):
            settings_dict[key] = int(defaults.get(key, '0'))

    try:
        users_list = json.loads(settings_dict.get('telegramUsers', '[]'))
        if isinstance(users_list, list) and all(isinstance(u, str) for u in users_list):
             settings_dict['telegramUsers'] = users_list
        else:
            settings_dict['telegramUsers'] = []
    except json.JSONDecodeError:
        settings_dict['telegramUsers'] = []

    return settings_dict

def update_setting(db: Session, key: str, value: str):
    setting = db.query(models.Setting).filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = models.Setting(key=key, value=value)
        db.add(setting)

def get_device_activity_threshold_time(db: Session) -> datetime.datetime:
    settings = get_all_settings(db)
    timeout_minutes = settings.get('deviceActivityTimeout', config.DEVICE_ACTIVITY_TIMEOUT_MINUTES)
    try:
        timeout_minutes = int(timeout_minutes)
    except (ValueError, TypeError):
        timeout_minutes = config.DEVICE_ACTIVITY_TIMEOUT_MINUTES

    timeout_minutes = max(1, timeout_minutes)
    return datetime.datetime.utcnow() - datetime.timedelta(minutes=timeout_minutes)

def check_inactive_devices_task(db: Session = None):
    if db is None:
        temp_db = SessionLocal()
    else:
        temp_db = db

    print(f"Starting the task to check inactive devices...")
    updated_count = 0
    alert_count = 0
    try:
        activity_threshold_time = get_device_activity_threshold_time(temp_db)
        devices_to_mark_inactive = temp_db.query(models.Device).filter(
            models.Device.last_seen < activity_threshold_time,
            models.Device.is_considered_active == True
        ).all()

        if not devices_to_mark_inactive:
            print("No devices found to mark as inactive.")
            return

        print(f"Found {len(devices_to_mark_inactive)} device(s) that became inactive.")

        macs_to_update = []

        for device in devices_to_mark_inactive:
            macs_to_update.append(device.mac_address)
            if device.status == 'trusted':
                severity = "Info"
                badge_color = "info"
                message = (f"Доверенное устройство перестало быть активным:\n"
                           f"IP={device.ip_address}, MAC={device.mac_address}\n"
                           f"Производитель: {device.vendor or 'Неизвестен'}\n"
                           f"Имя/Заметка: {device.notes or '(нет)'}")
            elif device.status == 'untrusted':
                severity = "Info"
                badge_color = "info"
                message = (f"Недоверенное устройство перестало быть активным:\n"
                           f"IP={device.ip_address}, MAC={device.mac_address}\n"
                           f"Производитель: {device.vendor or 'Неизвестен'}\n"
                           f"Имя/Заметка: {device.notes or '(нет)'}")
            else:
                severity = "Warning"
                badge_color = "warning"
                message = (f"Заблокированное устройство перестало быть активным:\n"
                           f"IP={device.ip_address}, MAC={device.mac_address}\n"
                           f"Производитель: {device.vendor or 'Неизвестен'}\n"
                           f"Имя/Заметка: {device.notes or '(нет)'}")

            create_alert(
                db=temp_db,
                message=message,
                severity=severity,
                badge_color=badge_color
            )
            alert_count += 1
        
        if macs_to_update:
            stmt = update(models.Device).\
                   where(models.Device.mac_address.in_(macs_to_update)).\
                   values(is_considered_active=False)
            result = temp_db.execute(stmt)
            updated_count = result.rowcount
            print(f"Set is_considered_active=False flag for {updated_count} devices.")
        
        if alert_count > 0 or updated_count > 0:
            temp_db.commit()
            print(f"Saved {alert_count} alerts and {updated_count} activity status updates.")

    except Exception as e:
        print(f"Error in the inactive devices check task: {e}")
        import traceback
        traceback.print_exc()
        if temp_db:
             temp_db.rollback()
    finally:
        if db is None and temp_db:
            temp_db.close()

def collect_interval_analytics_task():
    db = SessionLocal()
    try:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Running analytics collection task (triggered by report)...")
        settings = get_all_settings(db)
        interval_seconds = settings.get('analyticsCollectionIntervalSeconds', 300)
        if interval_seconds < 60:
            print(f"  Warning: Analytics collection interval ({interval_seconds}s) is too small, using 60s instead.")
            interval_seconds = 60

        now_utc = datetime.datetime.utcnow()
        total_seconds_since_epoch = (now_utc - datetime.datetime(1970, 1, 1)).total_seconds()
        interval_end_seconds_epoch = (total_seconds_since_epoch // interval_seconds) * interval_seconds
        interval_end_utc = datetime.datetime.utcfromtimestamp(interval_end_seconds_epoch)
        interval_start_utc = interval_end_utc - datetime.timedelta(seconds=interval_seconds)

        print(f"  - Calculating analytics for interval ending at: {interval_end_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")

        existing_record = db.query(models.AnalyticsIntervalData).filter_by(timestamp=interval_end_utc).first()

        active_device_count = 0
        try:
            activity_threshold_time_for_devices = interval_end_utc - datetime.timedelta(minutes=settings.get('deviceActivityTimeout', 60))
            active_device_count = db.query(func.count(models.Device.id)).filter(
                models.Device.last_seen >= activity_threshold_time_for_devices
            ).scalar() or 0
            print(f"  - Active devices calculated: {active_device_count}")
        except Exception as e_dev:
            print(f"  - Error while counting active devices: {e_dev}")
            active_device_count = existing_record.active_device_count if existing_record else 0

        warning_alerts = 0
        critical_alerts = 0
        info_alerts = 0
        try:
            # Count alerts WITHIN the specific interval
            alerts_in_interval = db.query(
                models.Alert.severity,
                func.count(models.Alert.id).label('count')
            ).filter(
                models.Alert.timestamp >= interval_start_utc,
                models.Alert.timestamp < interval_end_utc
            ).group_by(models.Alert.severity).all()

            for severity, count in alerts_in_interval:
                if severity == 'Warning':
                    warning_alerts = count
                elif severity in ['High', 'Critical']:
                    critical_alerts += count
                elif severity == 'Info':
                    info_alerts = count
            print(f"  - Alerts calculated: Info={info_alerts}, Warn={warning_alerts}, Crit/High={critical_alerts}")
        except Exception as e_alert:
            print(f"  - Error while counting alerts: {e_alert}")
            if existing_record:
                warning_alerts = existing_record.warning_alert_count
                critical_alerts = existing_record.critical_alert_count
                info_alerts = existing_record.info_alert_count
        
        if existing_record:
            print(f"  - Updating existing analytics record for {interval_end_utc.strftime('%H:%M:%S')}")
            existing_record.active_device_count = active_device_count
            existing_record.warning_alert_count = warning_alerts
            existing_record.critical_alert_count = critical_alerts
            existing_record.info_alert_count = info_alerts
        else:
            print(f"  - Inserting new analytics record for {interval_end_utc.strftime('%H:%M:%S')}")
            new_record = models.AnalyticsIntervalData(
                timestamp=interval_end_utc,
                interval_seconds=interval_seconds,
                active_device_count=active_device_count,
                warning_alert_count=warning_alerts,
                critical_alert_count=critical_alerts,
                info_alert_count=info_alerts
            )
            db.add(new_record)

        db.commit()
        print(f"  - Analytics data saved successfully for {interval_end_utc.strftime('%H:%M:%S')}.")

    except Exception as e:
        print(f"Error in the interval analytics collection task: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()
