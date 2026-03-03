"""Конфигурация сервиса."""

from typing import Annotated
from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode


class Settings(BaseSettings):
    # ── Keycloak ──────────────────────────────────────────
    keycloak_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: str

    # ── Приложение ────────────────────────────────────────
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False

    # ── БД ────────────────────────────────────────────────
    db_path: str = "tinode_keycloak.db"

    # ── Теги ──────────────────────────────────────────────
    restricted_tag_ns: Annotated[list[str], NoDecode] = ["rest", "email", "uname"]
    @ field_validator("restricted_tag_ns", mode="before")
    @ classmethod
    def parse_restricted_tag_ns(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value
    login_validation_re: str = r"^[a-zA-Z0-9_.\-@]{3,64}$"

    # ── Computed ──────────────────────────────────────────
    @property
    def token_url(self) -> str:
        return (
            f"{self.keycloak_url}/realms/{self.keycloak_realm}"
            f"/protocol/openid-connect/token"
        )

    @property
    def userinfo_url(self) -> str:
        return (
            f"{self.keycloak_url}/realms/{self.keycloak_realm}"
            f"/protocol/openid-connect/userinfo"
        )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


cfg = Settings()