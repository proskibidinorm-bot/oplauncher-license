from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base


def utcnow():
    return datetime.now(timezone.utc)


class AdminKey(Base):
    """Singleton-ish admin credentials. Created once on first startup."""
    __tablename__ = "admin_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(128), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_used_at = Column(DateTime(timezone=True), nullable=True)


class LicenseKey(Base):
    __tablename__ = "license_keys"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(64), unique=True, nullable=False, index=True)
    duration_minutes = Column(Integer, nullable=False)  # 1, 2, 5, 10
    max_devices = Column(Integer, nullable=False, default=1)

    # Status: pending | active | expired | blocked | revoked
    status = Column(String(20), nullable=False, default="pending", index=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    activated_at = Column(DateTime(timezone=True), nullable=True)  # first successful activation
    expires_at = Column(DateTime(timezone=True), nullable=True)    # activated_at + duration
    blocked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    note = Column(Text, nullable=True)

    devices = relationship("DeviceBinding", back_populates="license", cascade="all, delete-orphan")
    activations = relationship("ActivationLog", back_populates="license", cascade="all, delete-orphan")


class DeviceBinding(Base):
    __tablename__ = "device_bindings"
    __table_args__ = (UniqueConstraint("license_id", "device_id", name="uq_license_device"),)

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("license_keys.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String(128), nullable=False, index=True)
    device_name = Column(String(256), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    license = relationship("LicenseKey", back_populates="devices")


class ActivationLog(Base):
    __tablename__ = "activation_logs"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("license_keys.id", ondelete="CASCADE"), nullable=True)
    device_id = Column(String(128), nullable=False)
    action = Column(String(32), nullable=False)  # activate | check | fail | block | revoke | unblock
    success = Column(Boolean, default=True)
    message = Column(String(512), nullable=True)
    ip = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    license = relationship("LicenseKey", back_populates="activations")
