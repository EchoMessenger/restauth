"""Конфигурация сервиса."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Keycloak ──────────────────────────────────────────
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "tinode"
    keycloak_client_id: str = "tinode-server"
    keycloak_client_secret: str = ""

    # ── Приложение ────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False

    # ── БД ────────────────────────────────────────────────
    db_path: str = "tinode_keycloak.db"

    # ── Теги ──────────────────────────────────────────────
    restricted_tag_ns: list[str] = ["rest", "email", "uname"]
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