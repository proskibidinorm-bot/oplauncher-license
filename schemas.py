from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class ActivateRequest(BaseModel):
    key: str = Field(..., min_length=8, max_length=64)
    device_id: str = Field(..., min_length=8, max_length=128)
    device_name: Optional[str] = None


class CheckRequest(BaseModel):
    key: str = Field(..., min_length=8, max_length=64)
    device_id: str = Field(..., min_length=8, max_length=128)


class LicenseStatusResponse(BaseModel):
    valid: bool
    status: str
    message: str
    expires_at: Optional[datetime] = None
    remaining_seconds: Optional[int] = None
    duration_minutes: Optional[int] = None
    max_devices: Optional[int] = None
    devices_used: Optional[int] = None
    server_time: datetime


class GenerateKeyRequest(BaseModel):
    duration_minutes: int = Field(..., description="0=forever, or minutes")
    max_devices: int = Field(1, ge=1, le=50)
    note: Optional[str] = None
    count: int = Field(1, ge=1, le=50)


class GeneratedKey(BaseModel):
    key: str
    duration_minutes: int
    max_devices: int
    status: str
    created_at: datetime


class GenerateKeyResponse(BaseModel):
    keys: List[GeneratedKey]


class DeviceInfo(BaseModel):
    device_id: str
    device_name: Optional[str]
    first_seen: datetime
    last_seen: datetime


class LicenseInfo(BaseModel):
    key: str
    duration_minutes: int
    max_devices: int
    status: str
    created_at: datetime
    activated_at: Optional[datetime]
    expires_at: Optional[datetime]
    blocked_at: Optional[datetime]
    revoked_at: Optional[datetime]
    note: Optional[str]
    devices_used: int
    devices: List[DeviceInfo] = []


class LicenseListResponse(BaseModel):
    total: int
    items: List[LicenseInfo]


class ActionRequest(BaseModel):
    key: str


class ActivationLogItem(BaseModel):
    id: int
    key: str
    device_id: str
    action: str
    success: bool
    message: Optional[str]
    ip: Optional[str]
    created_at: datetime


class AdminLoginRequest(BaseModel):
    admin_key: str


class AdminLoginResponse(BaseModel):
    token: str
    expires_in: int


class MessageResponse(BaseModel):
    ok: bool
    message: str
