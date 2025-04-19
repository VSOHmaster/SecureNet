import datetime
import uuid
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.orm import relationship, Session
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Union

from .database import Base

class Agent(Base):
    __tablename__ = 'agents'
    id = Column(Integer, primary_key=True)
    agent_ext_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    ip_address = Column(String(45))
    agent_type = Column(String(50))
    parent_agent_id = Column(Integer, ForeignKey('agents.id'))
    links = Column(Text)
    status = Column(String(20), default='inactive', nullable=False)
    activity_level = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    api_key = Column(String(64), unique=True, index=True, nullable=False, default=lambda: Agent.generate_api_key())

    def __repr__(self):
        return f"<Agent(id={self.id}, ext_id='{self.agent_ext_id}', name='{self.name}', status='{self.status}')>"

    @staticmethod
    def generate_api_key():
        return str(uuid.uuid4()).replace('-', '')

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    mac_address = Column(String(17), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    vendor = Column(String(100), default='Unknown')
    status = Column(String(20), default='untrusted', nullable=False)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    notes = Column(Text)
    is_considered_active = Column(Boolean, default=True, nullable=False, server_default='true')

    def __repr__(self):
        return f"<Device(id={self.id}, mac='{self.mac_address}', ip='{self.ip_address}', status='{self.status}', active={self.is_considered_active})>"

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    badge_color = Column(String(20), default='secondary')
    acknowledged = Column(Boolean, default=False)

    def __repr__(self):
        return f"<Alert(id={self.id}, time='{self.timestamp}', severity='{self.severity}', msg='{self.message[:30]}...')>"


class Setting(Base):
    __tablename__ = 'settings'
    key = Column(String(100), primary_key=True)
    value = Column(Text)
    description = Column(Text)

    def __repr__(self):
        return f"<Setting(key='{self.key}', value='{self.value}')>"

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(64), index=True, unique=True, nullable=False)
    email = Column(String(120), index=True, unique=True, nullable=True)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

    @staticmethod
    def get_by_username(db: Session, username: str) -> Union['User', None]:
      return db.query(User).filter(User.username == username).first()

    @staticmethod
    def get_by_id(db: Session, user_id: int) -> Union['User', None]:
        return db.query(User).get(user_id)

class AnalyticsIntervalData(Base):
    __tablename__ = 'analytics_interval_data'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True, unique=True)
    interval_seconds = Column(Integer, nullable=False)
    active_device_count = Column(Integer, nullable=False, default=0)
    warning_alert_count = Column(Integer, nullable=False, default=0)
    critical_alert_count = Column(Integer, nullable=False, default=0)
    info_alert_count = Column(Integer, nullable=False, default=0)

    def __repr__(self):
        return (f"<AnalyticsIntervalData(time='{self.timestamp}', interval={self.interval_seconds}s, "
                f"dev={self.active_device_count}, warn={self.warning_alert_count}, "
                f"crit={self.critical_alert_count}, info={self.info_alert_count})>")
