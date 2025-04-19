from pydantic import BaseModel, Field, validator, EmailStr
from typing import List, Optional, Dict, Union
import datetime

class DeviceInfo(BaseModel):
    mac: str
    ip: str

class AgentReport(BaseModel):
    agent_id: str
    timestamp: Union[datetime.datetime, str]
    discovered_devices: List[DeviceInfo] = []
    agent_name: Optional[str] = None
    ip_address: Optional[str] = None

class AgentConfigResponse(BaseModel):
    scan_interval: int = Field(..., description="Scan interval in seconds")
    scan_timeout: int = Field(..., description="ARP scan timeout in seconds")
    network_cidr: str = Field(..., description="Network CIDR to scan")

# class UserBase(BaseModel):
#     username: str
#     email: Optional[EmailStr] = None
#     is_admin: bool = False

# class UserCreate(UserBase):
#     password: str

# class User(UserBase):
#     id: int

#     class Config:
#         orm_mode = True
