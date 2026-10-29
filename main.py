"""
OpLauncher License Server
FastAPI + SQLAlchemy (SQLite or PostgreSQL)
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Request, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from config import get_settings
from database import engine, Base, get_db, SessionLocal
from models import AdminKey, LicenseKey, DeviceBinding, ActivationLog, utcnow
from schemas import (
    ActivateRequest, CheckRequest, LicenseStatusResponse,
    GenerateKeyRequest, GenerateKeyResponse, GeneratedKey,
    LicenseInfo, LicenseListResponse, DeviceInfo,
    ActionRequest, ActivationLogItem, AdminLoginRequest, AdminLoginResponse,
    MessageResponse,
)
from security import hash_key, generate_license_key, create_admin_token, require_admin

settings = get_settings()

app = FastAPI(
    title="OpLauncher License Server",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(AdminKey).first()
        if not existing:
            raw_admin = "ADM-" + secrets.token_urlsafe(32)
            ak = AdminKey(key_hash=hash_key(raw_admin))
            db.add(ak)
            db.commit()
            # Write once to a protected file so the owner can retrieve it
            path = "ADMIN_KEY.txt"
            with open(path, "w") as f:
                f.write(
                    "# OpLauncher Admin Key — KEEP SECRET\n"
                    "# Generated on first server start. Delete this file after copying.\n"
                    f"{raw_admin}\n"
                )
            try:
                import os
                os.chmod(path, 0o600)
            except Exception:
                pass
            print("=" * 60)
            print("ADMIN KEY GENERATED (also written to ADMIN_KEY.txt):")
            print(raw_admin)
            print("=" * 60)
        else:
            print("Admin key already exists in DB (hash only).")
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()


def client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def refresh_status(lic: LicenseKey, now: datetime) -> str:
    """Update status based on server time. Never trust client clock."""
    if lic.status in ("blocked", "revoked"):
        return lic.status
    # duration_minutes == 0 → lifetime, never expires by time
    if lic.duration_minutes == 0:
        return lic.status if lic.status != "expired" else "active"
    if lic.activated_at and lic.expires_at:
        exp = lic.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now >= exp:
            if lic.status != "expired":
                lic.status = "expired"
            return "expired"
    return lic.status


def remaining_seconds(lic: LicenseKey, now: datetime) -> Optional[int]:
    if lic.duration_minutes == 0:
        return None  # forever
    if not lic.expires_at:
        return None
    exp = lic.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    delta = (exp - now).total_seconds()
    return max(0, int(delta))


def log_action(
    db: Session,
    lic: Optional[LicenseKey],
    device_id: str,
    action: str,
    success: bool,
    message: str,
    ip: Optional[str],
):
    entry = ActivationLog(
        license_id=lic.id if lic else None,
        device_id=device_id or "",
        action=action,
        success=success,
        message=message[:500] if message else None,
        ip=ip,
    )
    # license_id may be null for unknown keys — make column nullable for that case
    if lic is None:
        # skip FK if no license; we still want a log. Use a separate table or allow null.
        # For simplicity store with license_id=None only if column allows; we set nullable above? 
        # models has nullable=False. So only log when we have a license.
        return
    db.add(entry)


# ---------- Public endpoints ----------

@app.get("/health")
def health():
    return {"ok": True, "server_time": utcnow().isoformat()}


@app.post("/api/v1/activate", response_model=LicenseStatusResponse)
def activate(body: ActivateRequest, request: Request, db: Session = Depends(get_db)):
    now = utcnow()
    ip = client_ip(request)
    key = body.key.strip().upper()
    device_id = body.device_id.strip()

    lic = db.query(LicenseKey).filter(LicenseKey.key == key).first()
    if not lic:
        return LicenseStatusResponse(
            valid=False, status="invalid", message="Ключ не найден",
            server_time=now,
        )

    status_now = refresh_status(lic, now)

    if status_now == "blocked":
        log_action(db, lic, device_id, "fail", False, "Ключ заблокирован", ip)
        db.commit()
        return LicenseStatusResponse(
            valid=False, status="blocked", message="Ключ заблокирован",
            server_time=now,
        )
    if status_now == "revoked":
        log_action(db, lic, device_id, "fail", False, "Ключ отозван", ip)
        db.commit()
        return LicenseStatusResponse(
            valid=False, status="revoked", message="Ключ отозван",
            server_time=now,
        )
    if status_now == "expired":
        log_action(db, lic, device_id, "fail", False, "Срок действия истёк", ip)
        db.commit()
        return LicenseStatusResponse(
            valid=False, status="expired", message="Срок действия истёк",
            expires_at=lic.expires_at, remaining_seconds=0,
            duration_minutes=lic.duration_minutes, server_time=now,
        )

    # Device limit
    existing = db.query(DeviceBinding).filter(
        DeviceBinding.license_id == lic.id,
        DeviceBinding.device_id == device_id,
    ).first()

    if not existing:
        used = db.query(DeviceBinding).filter(DeviceBinding.license_id == lic.id).count()
        if used >= lic.max_devices:
            log_action(db, lic, device_id, "fail", False, "Достигнут лимит устройств", ip)
            db.commit()
            return LicenseStatusResponse(
                valid=False, status=status_now, message="Достигнут лимит устройств",
                max_devices=lic.max_devices, devices_used=used, server_time=now,
            )
        binding = DeviceBinding(
            license_id=lic.id,
            device_id=device_id,
            device_name=(body.device_name or "")[:256] or None,
        )
        db.add(binding)
    else:
        existing.last_seen = now
        if body.device_name:
            existing.device_name = body.device_name[:256]

    # First activation starts the timer (or marks lifetime key active)
    if lic.activated_at is None:
        lic.activated_at = now
        if lic.duration_minutes == 0:
            lic.expires_at = None  # навсегда
        else:
            lic.expires_at = now + timedelta(minutes=lic.duration_minutes)
        lic.status = "active"
    else:
        # Re-activation does NOT reset the timer
        if lic.status == "pending":
            lic.status = "active"

    status_now = refresh_status(lic, now)
    db.commit()

    devices_used = db.query(DeviceBinding).filter(DeviceBinding.license_id == lic.id).count()
    log_action(db, lic, device_id, "activate", True, "Активация успешна", ip)
    db.commit()

    return LicenseStatusResponse(
        valid=status_now == "active",
        status=status_now,
        message="Активация успешна" if status_now == "active" else f"Статус: {status_now}",
        expires_at=lic.expires_at,
        remaining_seconds=remaining_seconds(lic, now),
        duration_minutes=lic.duration_minutes,
        max_devices=lic.max_devices,
        devices_used=devices_used,
        server_time=now,
    )


@app.post("/api/v1/check", response_model=LicenseStatusResponse)
def check(body: CheckRequest, request: Request, db: Session = Depends(get_db)):
    now = utcnow()
    ip = client_ip(request)
    key = body.key.strip().upper()
    device_id = body.device_id.strip()

    lic = db.query(LicenseKey).filter(LicenseKey.key == key).first()
    if not lic:
        return LicenseStatusResponse(
            valid=False, status="invalid", message="Ключ не найден", server_time=now,
        )

    status_now = refresh_status(lic, now)
    if status_now != lic.status:
        db.commit()

    if status_now in ("blocked", "revoked", "expired", "pending"):
        msg = {
            "blocked": "Ключ заблокирован",
            "revoked": "Ключ отозван",
            "expired": "Срок действия истёк",
            "pending": "Ключ ещё не активирован",
        }.get(status_now, status_now)
        return LicenseStatusResponse(
            valid=False, status=status_now, message=msg,
            expires_at=lic.expires_at,
            remaining_seconds=remaining_seconds(lic, now) if status_now == "expired" else None,
            duration_minutes=lic.duration_minutes,
            server_time=now,
        )

    # Must be bound to this device
    binding = db.query(DeviceBinding).filter(
        DeviceBinding.license_id == lic.id,
        DeviceBinding.device_id == device_id,
    ).first()
    if not binding:
        return LicenseStatusResponse(
            valid=False, status="device_mismatch",
            message="Это устройство не привязано к ключу",
            server_time=now,
        )

    binding.last_seen = now
    devices_used = db.query(DeviceBinding).filter(DeviceBinding.license_id == lic.id).count()
    log_action(db, lic, device_id, "check", True, "Проверка OK", ip)
    db.commit()

    return LicenseStatusResponse(
        valid=True,
        status="active",
        message="Лицензия действительна",
        expires_at=lic.expires_at,
        remaining_seconds=remaining_seconds(lic, now),
        duration_minutes=lic.duration_minutes,
        max_devices=lic.max_devices,
        devices_used=devices_used,
        server_time=now,
    )


# ---------- Admin endpoints ----------

@app.post("/api/v1/admin/login", response_model=AdminLoginResponse)
def admin_login(body: AdminLoginRequest, db: Session = Depends(get_db)):
    h = hash_key(body.admin_key.strip())
    ak = db.query(AdminKey).filter(AdminKey.key_hash == h).first()
    if not ak:
        raise HTTPException(status_code=401, detail="Неверный ключ администратора")
    ak.last_used_at = utcnow()
    db.commit()
    token = create_admin_token()
    return AdminLoginResponse(token=token, expires_in=8 * 3600)


@app.post("/api/v1/admin/generate", response_model=GenerateKeyResponse)
def admin_generate(
    body: GenerateKeyRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    # 0 = навсегда; иначе любое положительное число минут
    if body.duration_minutes < 0:
        raise HTTPException(400, "duration_minutes: 0 (навсегда) или положительное число минут")
    keys: List[GeneratedKey] = []
    for _ in range(body.count):
        for attempt in range(20):
            k = generate_license_key()
            if not db.query(LicenseKey).filter(LicenseKey.key == k).first():
                break
        else:
            raise HTTPException(500, "Не удалось сгенерировать уникальный ключ")
        lic = LicenseKey(
            key=k,
            duration_minutes=body.duration_minutes,  # 0 = forever
            max_devices=body.max_devices,
            status="pending",
            note=body.note,
        )
        db.add(lic)
        keys.append(GeneratedKey(
            key=k,
            duration_minutes=body.duration_minutes,
            max_devices=body.max_devices,
            status="pending",
            created_at=utcnow(),
        ))
    db.commit()
    return GenerateKeyResponse(keys=keys)


@app.get("/api/v1/admin/licenses", response_model=LicenseListResponse)
def admin_list(
    q: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    now = utcnow()
    query = db.query(LicenseKey)
    if q:
        like = f"%{q.strip().upper()}%"
        query = query.filter(or_(LicenseKey.key.ilike(like), LicenseKey.note.ilike(f"%{q}%")))
    if status_filter:
        query = query.filter(LicenseKey.status == status_filter)

    total = query.count()
    rows = query.order_by(desc(LicenseKey.created_at)).offset(offset).limit(limit).all()

    items: List[LicenseInfo] = []
    for lic in rows:
        refresh_status(lic, now)
        devices = [
            DeviceInfo(
                device_id=d.device_id,
                device_name=d.device_name,
                first_seen=d.first_seen,
                last_seen=d.last_seen,
            )
            for d in lic.devices
        ]
        items.append(LicenseInfo(
            key=lic.key,
            duration_minutes=lic.duration_minutes,
            max_devices=lic.max_devices,
            status=lic.status,
            created_at=lic.created_at,
            activated_at=lic.activated_at,
            expires_at=lic.expires_at,
            blocked_at=lic.blocked_at,
            revoked_at=lic.revoked_at,
            note=lic.note,
            devices_used=len(devices),
            devices=devices,
        ))
    db.commit()
    return LicenseListResponse(total=total, items=items)


@app.post("/api/v1/admin/block", response_model=MessageResponse)
def admin_block(
    body: ActionRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    lic = db.query(LicenseKey).filter(LicenseKey.key == body.key.strip().upper()).first()
    if not lic:
        raise HTTPException(404, "Ключ не найден")
    if lic.status == "revoked":
        return MessageResponse(ok=False, message="Ключ уже отозван")
    lic.status = "blocked"
    lic.blocked_at = utcnow()
    log_action(db, lic, "", "block", True, "Заблокирован администратором", None)
    db.commit()
    return MessageResponse(ok=True, message="Ключ заблокирован")


@app.post("/api/v1/admin/unblock", response_model=MessageResponse)
def admin_unblock(
    body: ActionRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    lic = db.query(LicenseKey).filter(LicenseKey.key == body.key.strip().upper()).first()
    if not lic:
        raise HTTPException(404, "Ключ не найден")
    if lic.status != "blocked":
        return MessageResponse(ok=False, message="Ключ не заблокирован")
    now = utcnow()
    if lic.expires_at:
        exp = lic.expires_at if lic.expires_at.tzinfo else lic.expires_at.replace(tzinfo=timezone.utc)
        if now >= exp:
            lic.status = "expired"
        else:
            lic.status = "active" if lic.activated_at else "pending"
    else:
        lic.status = "pending" if not lic.activated_at else "active"
    lic.blocked_at = None
    log_action(db, lic, "", "unblock", True, "Разблокирован администратором", None)
    db.commit()
    return MessageResponse(ok=True, message=f"Ключ разблокирован, статус: {lic.status}")


@app.post("/api/v1/admin/revoke", response_model=MessageResponse)
def admin_revoke(
    body: ActionRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    lic = db.query(LicenseKey).filter(LicenseKey.key == body.key.strip().upper()).first()
    if not lic:
        raise HTTPException(404, "Ключ не найден")
    lic.status = "revoked"
    lic.revoked_at = utcnow()
    log_action(db, lic, "", "revoke", True, "Отозван администратором", None)
    db.commit()
    return MessageResponse(ok=True, message="Ключ отозван")


@app.patch("/api/v1/admin/licenses/{key}/devices")
def admin_set_max_devices(
    key: str,
    max_devices: int = Query(..., ge=1, le=10),
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    lic = db.query(LicenseKey).filter(LicenseKey.key == key.strip().upper()).first()
    if not lic:
        raise HTTPException(404, "Ключ не найден")
    lic.max_devices = max_devices
    db.commit()
    return MessageResponse(ok=True, message=f"Лимит устройств: {max_devices}")


@app.get("/api/v1/admin/history", response_model=List[ActivationLogItem])
def admin_history(
    key: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    q = db.query(ActivationLog).join(LicenseKey)
    if key:
        q = q.filter(LicenseKey.key == key.strip().upper())
    rows = q.order_by(desc(ActivationLog.created_at)).limit(limit).all()
    result = []
    for r in rows:
        result.append(ActivationLogItem(
            id=r.id,
            key=r.license.key if r.license else "",
            device_id=r.device_id,
            action=r.action,
            success=r.success,
            message=r.message,
            ip=r.ip,
            created_at=r.created_at,
        ))
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
