"""
Tinode REST/JSON-RPC authentication service — Keycloak back-end (FastAPI).

Обязательные эндпоинты: /auth, /link, /rtagns
Остальные: unsupported
"""

import base64
import binascii
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from config_example import cfg
from models import (
    TinodeRequest,
    TinodeResponse,
    AuthRecordResponse,
    NewAccount,
    ErrorResponse,
)
from database import (
    init_db,
    get_by_keycloak_id,
    get_by_username,
    link_tinode_uid,
    upsert_user,
)
from keycloak_client import authenticate, get_userinfo

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if cfg.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tinode-rest-auth")


# ── Lifespan (инициализация БД при старте) ────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info(
        "Started Tinode REST auth (Keycloak: %s realm=%s)",
        cfg.keycloak_url,
        cfg.keycloak_realm,
    )
    yield


app = FastAPI(
    title="Tinode REST Auth — Keycloak",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Helpers ───────────────────────────────────────────────────


def _parse_secret(encoded: str) -> tuple[str | None, str | None]:
    try:
        raw = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None, None
    parts = raw.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None, None
    return parts[0], parts[1]


def _build_public(userinfo: dict) -> dict:
    fn = userinfo.get("name") or userinfo.get("preferred_username", "")
    public: dict = {"fn": fn}
    photo = userinfo.get("picture")
    if photo:
        public["photo"] = {"type": "url", "ref": photo}
    return public


def _err(msg: str) -> TinodeResponse:
    """Быстрый способ вернуть ошибку."""
    return TinodeResponse(err=msg)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Обязательные эндпоинты
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/auth", response_model=TinodeResponse, response_model_exclude_none=True)
async def auth_endpoint(body: TinodeRequest):
    """Аутентификация пользователя через Keycloak."""

    if not body.secret:
        return _err("malformed")

    username, password = _parse_secret(body.secret)
    if username is None:
        return _err("malformed")

    # 1. Проверяем credentials в Keycloak
    token_data = await authenticate(username, password)
    if token_data is None or not isinstance(token_data, dict):
        return _err("failed")

    # 2. Получаем профиль
    access_token = token_data.get("access_token")
    if not access_token:
        return _err("internal")

    userinfo = await get_userinfo(access_token)
    if userinfo is None or not isinstance(userinfo, dict):
        return _err("internal")

    keycloak_id = userinfo.get("sub")
    if not isinstance(keycloak_id, str) or not keycloak_id:
        return _err("internal")
    email: str = userinfo.get("email", "")
    preferred: str = userinfo.get("preferred_username", username)

    # 3. Проверяем маппинг
    mapping = await get_by_keycloak_id(keycloak_id)

    if mapping and mapping.get("tinode_uid"):
        # Повторный вход — аккаунт уже существует
        logger.info("User %s authenticated, uid=%s", preferred, mapping["tinode_uid"])
        return TinodeResponse(
            rec=AuthRecordResponse(
                uid=mapping["tinode_uid"],
                authlvl="auth",
                features=0,
                state="ok",
            )
        )

    # 4. Первый вход — просим Tinode создать аккаунт
    await upsert_user(keycloak_id, preferred)

    tags = [f"uname:{preferred}"]
    if email:
        tags.append(f"email:{email}")

    logger.info("First login for %s — requesting new Tinode account", preferred)

    return TinodeResponse(
        rec=AuthRecordResponse(
            authlvl="auth",
            tags=tags,
            features=0,
            state="ok",
        ),
        newacc=NewAccount(
            public=_build_public(userinfo),
            trusted={},
            private={},
        ),
    )


@app.post("/link", response_model=TinodeResponse, response_model_exclude_none=True)
async def link_endpoint(body: TinodeRequest):
    """Привязка Tinode UID к учётной записи Keycloak."""

    if not body.rec or not body.rec.uid or not body.secret:
        return _err("malformed")

    username, password = _parse_secret(body.secret)
    if username is None:
        return _err("malformed")

    token_data = await authenticate(username, password)
    if token_data is None or not isinstance(token_data, dict):
        return _err("failed")

    access_token = token_data.get("access_token")
    if not access_token:
        return _err("internal")

    userinfo = await get_userinfo(access_token)
    if userinfo is None or not isinstance(userinfo, dict):
        return _err("internal")
    sub = userinfo.get("sub")
    if not isinstance(sub, str) or not sub:
        return _err("internal")

    mapping = await get_by_keycloak_id(sub)
    if mapping is None:
        return _err("not found")

    if mapping.get("tinode_uid"):
        return _err("duplicate value")

    if not await link_tinode_uid(mapping["keycloak_username"], body.rec.uid):
        return _err("internal")

    logger.info("Linked %s → %s", username, body.rec.uid)

    # Успех — пустой JSON-объект
    return TinodeResponse()


@app.post("/rtagns", response_model=TinodeResponse, response_model_exclude_none=True)
async def rtagns_endpoint():
    """Список restricted tag namespaces."""
    return TinodeResponse(
        strarr=cfg.restricted_tag_ns,
        byteval=base64.b64encode(
            cfg.login_validation_re.encode()
        ).decode("utf-8"),
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Неподдерживаемые эндпоинты
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/add")
@app.post("/checkunique")
@app.post("/del")
@app.post("/gen")
@app.post("/upd")
async def unsupported_endpoint():
    return ErrorResponse(err="unsupported")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Обработка ошибок
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/")
async def index():
    return {"message": "Tinode REST auth service (Keycloak backend)"}


@app.exception_handler(404)
async def handle_404(request: Request, exc):
    return JSONResponse(status_code=404, content={"err": "not found"})


@app.exception_handler(405)
async def handle_405(request: Request, exc):
    return JSONResponse(status_code=405, content={"err": "method not allowed"})


@app.exception_handler(500)
async def handle_500(request: Request, exc):
    return JSONResponse(status_code=500, content={"err": "internal"})


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=cfg.host,
        port=cfg.port,
        reload=cfg.debug,
    )