import datetime
from datetime import timedelta
from fastapi_utils.tasks import repeat_every
from sqlalchemy import distinct
import random
import json
import os
import time
import traceback
from typing import List, Optional, Dict, Union, Any

from fastapi import (
    FastAPI, Request, Depends, Form, HTTPException, Header, Body, Query, Path,
    status, Response as FastAPIResponse, BackgroundTasks
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, func
import threading

from . import core, models, utils, schemas
from .database import SessionLocal, engine, init_db
from .config import config
from .dependencies import get_db, get_current_user, get_current_user_or_none, require_admin
from .auth import (
    create_session_cookie, delete_session_cookie,
    set_flash_message, get_flashed_messages,
    SESSION_COOKIE_NAME
)

UserOrNone = Union[models.User, None]

app = FastAPI(title="SecureNet API", version="1.0.0")

templates = Jinja2Templates(directory="server/templates")

async def check_inactive_agents_task():
    db: Session = SessionLocal()
    updated_count = 0
    try:
        settings = core.get_all_settings(db)
        timeout_seconds = settings.get('responseTimeout', 300)
        if timeout_seconds <= 0:
            timeout_seconds = 300

        threshold_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=timeout_seconds)

        agents_to_deactivate = db.query(models.Agent).filter(
            models.Agent.status == 'active',
            models.Agent.last_seen < threshold_time
        ).all()

        if not agents_to_deactivate:
            db.close()
            return

        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Найдено {len(agents_to_deactivate)} агент(ов) для деактивации.")

        for agent in agents_to_deactivate:
            agent.status = 'inactive'
            core.create_alert(
                db=db,
                message=f"Агент '{agent.name}' ({agent.ip_address or 'IP не указан'}) стал неактивным (таймаут: {timeout_seconds}s).",
                severity="Warning",
                badge_color="warning"
            )
            updated_count += 1

        if updated_count > 0:
            db.commit()
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Статус {updated_count} агент(ов) изменен на 'inactive'.")

    except Exception as e:
        print(f"Фоновая задача: Ошибка при проверке неактивных агентов: {e}")
        import traceback
        traceback.print_exc()
        if db:
            db.rollback()
    finally:
        if db:
            db.close()

def render_template(
    template_name: str,
    context: dict,
    response_class=HTMLResponse
) -> FastAPIResponse:
    if "request" not in context:
        raise ValueError("'request' must be included in the context for TemplateResponse")
    return templates.TemplateResponse(template_name, context, response_class=response_class)

def apply_flash_cookie_headers(source_response: FastAPIResponse, target_response: FastAPIResponse):
    flash_cookie_header_key = "set-cookie"
    flash_cookie_name_part = SESSION_COOKIE_NAME + "_flash"
    for key, value in source_response.headers.items():
        if key.lower() == flash_cookie_header_key and flash_cookie_name_part in value:
            target_response.raw_headers.append(
                (key.encode('latin-1'), value.encode('latin-1'))
            )

def generate_hourly_labels(hours_ago=24) -> List[str]:
    now_utc = datetime.datetime.utcnow()
    labels = []
    for i in range(hours_ago, -1, -1):
        dt = now_utc - datetime.timedelta(hours=i)
        labels.append(dt.strftime('%H:00'))
    return labels

def fill_missing_hours(hourly_data: Dict[str, int], all_labels: List[str]) -> List[int]:
    return [hourly_data.get(label, 0) for label in all_labels]

@app.get("/login", response_class=HTMLResponse, name="login_page")
async def login_page(
    request: Request,
    next_url: Optional[str] = Query(None, alias="next"),
    current_user: UserOrNone = Depends(get_current_user_or_none)
):
    if current_user:
        home_url = request.url_for('home_page')
        return RedirectResponse(url=str(home_url), status_code=status.HTTP_303_SEE_OTHER)

    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Login", "next": next_url,
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("login.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.post("/login", response_class=RedirectResponse, name="login_action")
async def login_action(
    request: Request, username: str = Form(...), password: str = Form(...),
    remember: Optional[str] = Form(None), next_url: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = models.User.get_by_username(db, username)
    home_url = str(request.url_for('home_page'))
    login_url = str(request.url_for('login_page'))
    redirect_to = next_url if next_url and next_url.startswith("/") else home_url

    if user and user.check_password(password):
        response = RedirectResponse(url=redirect_to, status_code=status.HTTP_303_SEE_OTHER)
        remember_me = bool(remember)
        create_session_cookie(response, user.id, remember=remember_me)
        set_flash_message(response, f'Добро пожаловать, {user.username}!', 'success')
    else:
        login_redirect_url = login_url + (f"?next={next_url}" if next_url else "")
        response = RedirectResponse(url=login_redirect_url, status_code=status.HTTP_303_SEE_OTHER)
        set_flash_message(response, 'Неверное имя пользователя или пароль.', 'danger')
    return response

@app.get("/logout", response_class=RedirectResponse, name="logout")
async def logout(request: Request, current_user: models.User = Depends(get_current_user)):
    login_url = str(request.url_for('login_page'))
    response = RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)
    delete_session_cookie(response)
    set_flash_message(response, 'Вы успешно вышли из системы.', 'info')
    return response

@app.get("/", response_class=HTMLResponse, name="home_page")
async def home_page(request: Request, current_user: models.User = Depends(get_current_user)):
    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Home", "active": "home",
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("home.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.get("/agents", response_class=HTMLResponse, name="agents_page")
async def agents_page(request: Request, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    agents_list = db.query(models.Agent).order_by(models.Agent.id).all()
    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Agents", "active": "agents", "agents": agents_list,
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("agents.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.post("/agents", response_class=RedirectResponse, name="add_agent")
async def add_agent(
    request: Request, agentName: str = Form(...), agentIP: Optional[str] = Form(None),
    agentType: Optional[str] = Form(None), db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    agents_url = str(request.url_for('agents_page'))
    response = RedirectResponse(url=agents_url, status_code=status.HTTP_303_SEE_OTHER)
    new_api_key = models.Agent.generate_api_key()
    try:
        ext_id = f"manual_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))}"
        new_agent = models.Agent(
            agent_ext_id=ext_id,
            name=agentName,
            ip_address=agentIP if agentIP else None,
            agent_type=agentType if agentType else None,
            status='inactive',
            api_key=new_api_key
        )
        db.add(new_agent); db.commit(); db.refresh(new_agent)
        flash_msg = (f"Agent '{new_agent.name}' added. API Key: {new_api_key}. "
                     f"Save this key now, it will not be shown again!")
        set_flash_message(response, flash_msg, "success")
    except Exception as e:
        db.rollback()
        set_flash_message(response, f"Ошибка добавления агента: {e}", "danger")
    return response

@app.post("/agents/{agent_id}/delete", response_class=RedirectResponse, name="delete_agent")
async def delete_agent_action(
    request: Request,
    agent_id: int = Path(..., title="The ID of the agent to delete", ge=1),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    agents_url = str(request.url_for('agents_page'))
    response = RedirectResponse(url=agents_url, status_code=status.HTTP_303_SEE_OTHER)

    agent = db.query(models.Agent).filter(models.Agent.id == agent_id).first()

    if not agent:
        set_flash_message(response, f"Агент с ID {agent_id} не найден.", "danger")
        return response

    try:
        agent_name = agent.name
        db.delete(agent)
        db.commit()
        set_flash_message(response, f"Агент '{agent_name}' (ID: {agent_id}) удален.", "success")
        print(f"Agent {agent_id} deleted by user {current_user.username}")
    except Exception as e:
        db.rollback()
        set_flash_message(response, f"Ошибка удаления агента: {e}", "danger")
        print(f"Error deleting agent {agent_id}: {e}")
        if "violates foreign key constraint" in str(e).lower():
             set_flash_message(response, f"Ошибка удаления агента: существуют связанные данные.", "danger")
        traceback.print_exc()

    return response

@app.get("/devices", response_class=HTMLResponse, name="devices_page")
async def devices_page(request: Request, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    settings = core.get_all_settings(db)

    activity_threshold_minutes = settings.get('deviceActivityTimeout', config.DEVICE_ACTIVITY_TIMEOUT_MINUTES)
    try:
        activity_threshold_minutes = int(activity_threshold_minutes)
    except (ValueError, TypeError):
        activity_threshold_minutes = config.DEVICE_ACTIVITY_TIMEOUT_MINUTES
    
    activity_threshold_time = core.get_device_activity_threshold_time(db)
    all_devices_q = db.query(models.Device).order_by(desc(models.Device.last_seen))
    all_devices = all_devices_q.all()

    active_devices = [
        d for d in all_devices if d.last_seen >= activity_threshold_time
    ]

    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Devices", "active": "devices",
        "active_devices": active_devices,
        "all_devices": all_devices,
        "activity_threshold_minutes": activity_threshold_minutes,
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("devices.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.post("/devices/{device_id}/update", response_class=RedirectResponse, name="update_device")
async def update_device_details(
    request: Request,
    device_id: int = Path(..., title="The ID of the device to update", ge=1),
    new_status: Optional[str] = Form(None, alias="status"),
    notes: Optional[str] = Form(None),
    new_vendor: Optional[str] = Form(None, alias="vendor"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    devices_url = str(request.url_for('devices_page'))
    response = RedirectResponse(url=devices_url, status_code=status.HTTP_303_SEE_OTHER)

    device = db.query(models.Device).filter(models.Device.id == device_id).first()

    if not device:
        set_flash_message(response, f"Устройство с ID {device_id} не найдено.", "danger")
        return response

    try:
        updated = False
        if new_status is not None and new_status in ['trusted', 'untrusted', 'blocked']:
            if device.status != new_status:
                device.status = new_status
                updated = True
        if notes is not None:
            current_notes = device.notes if device.notes is not None else ""
            new_notes_stripped = notes.strip()
            if current_notes != new_notes_stripped:
                device.notes = new_notes_stripped
                updated = True
        if new_vendor is not None:
            vendor_to_save = new_vendor.strip()
            current_db_vendor = device.vendor if device.vendor is not None else ""
            if current_db_vendor != vendor_to_save:
                 device.vendor = vendor_to_save if vendor_to_save else "Unknown"
                 updated = True

        if updated:
            db.commit()
            set_flash_message(response, f"Данные устройства '{device.mac_address}' обновлены.", "success")
        else:
            set_flash_message(response, "Изменений не было.", "info")

    except Exception as e:
        db.rollback()
        set_flash_message(response, f"Ошибка обновления устройства: {e}", "danger")
        print(f"Error updating device {device_id}: {e}")
        traceback.print_exc()
    return response

@app.post("/devices/{device_id}/delete", response_class=RedirectResponse, name="delete_device")
async def delete_device_action(
    request: Request,
    device_id: int = Path(..., title="The ID of the device to delete", ge=1),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    devices_url = str(request.url_for('devices_page'))
    response = RedirectResponse(url=devices_url, status_code=status.HTTP_303_SEE_OTHER)

    device = db.query(models.Device).filter(models.Device.id == device_id).first()

    if not device:
        set_flash_message(response, f"Устройство с ID {device_id} не найдено.", "danger")
        return response

    try:
        mac_address = device.mac_address
        db.delete(device)
        db.commit()
        set_flash_message(response, f"Устройство '{mac_address}' (ID: {device_id}) удалено.", "success")
        print(f"Device {device_id} ({mac_address}) deleted by user {current_user.username}")
    except Exception as e:
        db.rollback()
        set_flash_message(response, f"Ошибка удаления устройства: {e}", "danger")
        print(f"Error deleting device {device_id}: {e}")
        traceback.print_exc()

    return response

@app.get("/alerts", response_class=HTMLResponse, name="alerts_page")
async def alerts_page(request: Request, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    alerts_list = db.query(models.Alert).order_by(desc(models.Alert.timestamp)).limit(200).all()
    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Alerts", "active": "alerts", "alerts": alerts_list,
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("alerts.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.get("/analytics", response_class=HTMLResponse, name="analytics_page")
async def analytics_page(request: Request, current_user: models.User = Depends(get_current_user)):
    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Analytics", "active": "analytics",
        "chart_connections": "", "chart_threats": "",
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("analytics.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.get("/settings", response_class=HTMLResponse, name="settings_page")
async def settings_page(
    request: Request, db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    all_settings = core.get_all_settings(db)
    system_settings = {
        k: all_settings[k] for k in [
            'scanInterval', 'scanTimeout', 'defaultNetworkCidr',
            'maxConnections', 'responseTimeout',
            'deviceActivityTimeout', 'ouiFileUrl'
        ] if k in all_settings
    }
    notification_settings = {
        k: all_settings[k] for k in [
            'notifyMethod', 'notificationSeverityThreshold', 'alertRepeatCooldown'
        ] if k in all_settings
    }
    telegram_config = {'botToken': all_settings.get('botToken',''), 'users': all_settings.get('telegramUsers',[])}
    email_config = {k: all_settings[k] for k in ['smtpServer', 'smtpPort', 'emailSender', 'emailPassword', 'emailRecipient'] if k in all_settings}

    temp_response_for_flash = FastAPIResponse()
    flashed_messages = get_flashed_messages(request, temp_response_for_flash)
    context = {
        "request": request, "title": "Settings", "active": "settings",
        "system_settings": system_settings,
        "notification_settings": notification_settings,
        "telegram_config": telegram_config, "email_config": email_config,
        "current_user": current_user, "get_flashed_messages": flashed_messages,
        "now": datetime.datetime.utcnow(), "config": config,
    }
    html_response = render_template("settings.html", context)
    apply_flash_cookie_headers(temp_response_for_flash, html_response)
    return html_response

@app.post("/settings", response_class=RedirectResponse, name="update_settings")
async def update_settings(
    request: Request, db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    settings_url = str(request.url_for('settings_page'))
    response = RedirectResponse(url=settings_url, status_code=status.HTTP_303_SEE_OTHER)
    data = await request.form()
    form_type = data.get("form_type")

    try:
        if form_type == "system":
            core.update_setting(db, 'scanInterval', data.get("scanInterval", '60'))
            core.update_setting(db, 'scanTimeout', data.get("scanTimeout", '5'))
            core.update_setting(db, 'defaultNetworkCidr', data.get("defaultNetworkCidr", '192.168.1.0/24'))
            core.update_setting(db, 'maxConnections', data.get("maxConnections", '100'))
            core.update_setting(db, 'responseTimeout', data.get("responseTimeout", '300'))
            core.update_setting(db, 'deviceActivityTimeout', data.get("deviceActivityTimeout", '60'))
            core.update_setting(db, 'ouiFileUrl', data.get("ouiFileUrl", config.OUI_FILE_URL))
            set_flash_message(response, "Системные настройки сохранены.", "success")
        elif form_type == "notifications":
            core.update_setting(db, 'notifyMethod', data.get("notifyMethod", 'None'))
            core.update_setting(db, 'notificationSeverityThreshold', data.get("notificationSeverityThreshold", 'Warning'))
            core.update_setting(db, 'alertRepeatCooldown', data.get("alertRepeatCooldown", '5'))
            set_flash_message(response, "Настройки уведомлений сохранены.", "success")
        elif form_type == "telegram":
            core.update_setting(db, 'botToken', data.get("botToken", ''))
            users = data.getlist("telegram_users")
            users_json = json.dumps([u.strip() for u in users if u and u.strip()])
            core.update_setting(db, 'telegramUsers', users_json)
            set_flash_message(response, "Настройки Telegram сохранены.", "success")
        elif form_type == "email":
            core.update_setting(db, 'smtpServer', data.get("smtpServer", ''))
            core.update_setting(db, 'smtpPort', data.get("smtpPort", '465'))
            core.update_setting(db, 'emailSender', data.get("emailSender", ''))
            email_password = data.get("emailPassword")
            password_updated = False
            if email_password:
                 core.update_setting(db, 'emailPassword', email_password)
                 password_updated = True
            core.update_setting(db, 'emailRecipient', data.get("emailRecipient", ''))
            msg = "Настройки Email сохранены"
            cat = "success"
            if password_updated:
                msg += " (пароль изменен)."
                cat = "warning"
            else:
                msg += " (пароль не изменен)."
            set_flash_message(response, msg, cat)
        else:
             set_flash_message(response, f"Неизвестный тип формы настроек: {form_type}", "warning")

        if form_type in ["system", "notifications", "telegram", "email"]:
            db.commit()
        else:
            pass # No commit if form type is unknown

    except Exception as e:
        db.rollback()
        set_flash_message(response, f"Ошибка сохранения настроек: {e}", "danger")
        print(f"Error saving settings (Form: {form_type}): {e}")
        traceback.print_exc()
    return response

@app.post("/settings/update-oui", response_class=RedirectResponse, name="update_oui_manual")
async def update_oui_manual(
    request: Request,
    oui_file_url_from_form: str = Form(..., alias="ouiFileUrl"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    settings_url = str(request.url_for('settings_page'))
    response = RedirectResponse(url=settings_url, status_code=status.HTTP_303_SEE_OTHER)

    try:
        url_to_save = oui_file_url_from_form.strip() if oui_file_url_from_form else config.OUI_FILE_URL
        if not url_to_save:
            url_to_save = config.OUI_FILE_URL
    
        current_settings = core.get_all_settings(db)
        current_db_url = current_settings.get('ouiFileUrl', config.OUI_FILE_URL)

        if url_to_save != current_db_url:
            core.update_setting(db, 'ouiFileUrl', url_to_save)
            db.commit()
            print(f"OUI URL setting updated to: {url_to_save} by user {current_user.username}")
            set_flash_message(response, f"URL для OUI сохранен: {url_to_save}", "info")
        else:
            print("OUI URL from form is the same as in DB, no update needed.")

    except Exception as e:
        db.rollback()
        print(f"Error saving OUI URL setting before update: {e}")
        set_flash_message(response, f"Ошибка сохранения URL для OUI: {e}", "danger")
    
    print(f"Manual OUI update triggered by user {current_user.username}...")
    success = utils.update_oui_data(force_download=True, db=db)

    if success:
        set_flash_message(response, "OUI database update successful.", "success")
        print("Manual OUI update successful.")
    else:
        set_flash_message(response, "Failed to update OUI database. Check server logs.", "danger")
        print("Manual OUI update failed.")
    return response

@app.post("/api/agent/report", status_code=status.HTTP_200_OK, response_model=Dict, name="agent_report")
async def handle_agent_report(
    agent_data: schemas.AgentReport,
    background_tasks: BackgroundTasks,
    x_api_key: Union[str, None] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Отсутствует заголовок X-API-Key")

    data_dict = agent_data.dict()
    result, status_code = core.process_agent_report(data_dict, x_api_key, db)

    if status_code >= 400:
        raise HTTPException(status_code=status_code, detail=result.get("message", "Ошибка обработки отчета агента"))
    
    background_tasks.add_task(check_inactive_agents_task)
    background_tasks.add_task(core.check_inactive_devices_task)
    background_tasks.add_task(core.collect_interval_analytics_task)
    return result

@app.get("/api/agent/config", response_model=schemas.AgentConfigResponse, name="get_agent_config")
async def get_agent_configuration(
    x_api_key: Union[str, None] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header")

    agent = core.verify_agent_api_key(x_api_key, db)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found for the provided API key")

    try:
        settings = core.get_all_settings(db)
        config_data = {
            "scan_interval": settings.get('scanInterval', 60),
            "scan_timeout": settings.get('scanTimeout', 5),
            "network_cidr": settings.get('defaultNetworkCidr', '192.168.1.0/24')
        }
        return config_data
    except Exception as e:
        print(f"Error fetching configuration for agent {agent.id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve agent configuration")

@app.get("/api/analytics/data", response_model=Dict, name="get_analytics_data")
async def get_analytics_data_endpoint(
    start_time_iso: Optional[str] = Query(None, description="Start time in ISO format (UTC)"),
    end_time_iso: Optional[str] = Query(None, description="End time in ISO format (UTC)"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    end_time_utc = datetime.datetime.utcnow()
    if end_time_iso:
        try:
            end_time_utc = datetime.datetime.fromisoformat(end_time_iso.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_time_iso format")

    start_time_utc = end_time_utc - datetime.timedelta(hours=24)
    if start_time_iso:
        try:
            start_time_utc = datetime.datetime.fromisoformat(start_time_iso.replace('Z', '+00:00'))
        except ValueError:
             raise HTTPException(status_code=400, detail="Invalid start_time_iso format")

    if start_time_utc >= end_time_utc:
         raise HTTPException(status_code=400, detail="Start time must be before end time")

    print(f"Requesting analytics data from {start_time_utc.isoformat()} to {end_time_utc.isoformat()}")

    all_labels = []
    device_data = []
    warning_alert_data = []
    critical_alert_data = []
    info_alert_data = []

    try:
        results = db.query(models.AnalyticsIntervalData).filter(
            models.AnalyticsIntervalData.timestamp >= start_time_utc,
            models.AnalyticsIntervalData.timestamp <= end_time_utc
        ).order_by(models.AnalyticsIntervalData.timestamp).all()

        for record in results:
            all_labels.append(record.timestamp.isoformat() + "Z")
            device_data.append(record.active_device_count)
            warning_alert_data.append(record.warning_alert_count)
            critical_alert_data.append(record.critical_alert_count)
            info_alert_data.append(record.info_alert_count)
        
        if not all_labels:
            print("Analytics data for the specified period not found.")

        return {
            "devices": {
                "labels": all_labels,
                "data": device_data
            },
            "alerts": {
                "labels": all_labels,
                "warning_data": warning_alert_data,
                "critical_data": critical_alert_data,
                "info_data": info_alert_data
            }
        }

    except Exception as e:
        print(f"Ошибка при получении данных интервальной аналитики: {e}")
        import traceback
        traceback.print_exc()
        return {
            "devices": {"labels": [], "data": []},
            "alerts": {"labels": [], "warning_data": [], "critical_data": [], "info_data": []}
        }

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FastAPIResponse(status_code=204)
