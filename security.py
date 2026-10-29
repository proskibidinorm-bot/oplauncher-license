import hashlib
import hmac
import secrets
import time
from typing import Optional
from fastapi import Header, HTTPException, status
from config import get_settings


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_license_key() -> str:
    """Format: OPL-XXXX-XXXX-XXXX-XXXX (readable, unique)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    parts = []
    for _ in range(4):
        parts.append("".join(secrets.choice(alphabet) for _ in range(4)))
    return "OPL-" + "-".join(parts)


def create_admin_token(ttl_seconds: int = 3600 * 8) -> str:
    settings = get_settings()
    exp = int(time.time()) + ttl_seconds
    payload = f"admin:{exp}"
    sig = hmac.new(
        settings.admin_jwt_secret.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{sig}"


def verify_admin_token(token: str) -> bool:
    settings = get_settings()
    try:
        payload, sig = token.rsplit(".", 1)
        expected = hmac.new(
            settings.admin_jwt_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        if not payload.startswith("admin:"):
            return False
        exp = int(payload.split(":", 1)[1])
        return time.time() < exp
    except Exception:
        return False


def require_admin(authorization: Optional[str] = Header(None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется токен администратора")
    token = authorization[7:].strip()
    if not verify_admin_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный или истёкший токен")
