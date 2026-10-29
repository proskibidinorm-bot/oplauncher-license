from pydantic_settings import BaseSettings
from functools import lru_cache
import secrets
import os


class Settings(BaseSettings):
    database_url: str = "sqlite:///./licenses.db"
    admin_jwt_secret: str = ""
    cors_origins: str = "*"
    host: str = "0.0.0.0"
    port: int = 8000

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.admin_jwt_secret:
        # Persist a stable secret next to the DB so restarts keep the same secret
        secret_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".admin_secret")
        if os.path.exists(secret_path):
            with open(secret_path, "r") as f:
                s.admin_jwt_secret = f.read().strip()
        else:
            s.admin_jwt_secret = secrets.token_urlsafe(48)
            with open(secret_path, "w") as f:
                f.write(s.admin_jwt_secret)
            try:
                os.chmod(secret_path, 0o600)
            except Exception:
                pass
    return s
