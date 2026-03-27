import base64
import binascii
import logging
from contextlib import asynccontextmanager
import traceback

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
    link_tinode_uid,
    upsert_user,
)
from keycloak_client import verify_jwt

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if cfg.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tinode-rest-auth")


# ── Lifespan ──────────────────────────────────────────────────
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
    version="2.0.0",
    lifespan=lifespan,
)


# ── Helpers ───────────────────────────────────────────────────


def _decode_secret(encoded: str) -> str | None:
    """
    Декодирует secret из Tinode и возвращает JWT.

    Ожидаемый формат:
      base64("<login>:<jwt>")

    Возвращает None при любой ошибке декодирования или при пустом токене.
    """
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8").strip()
    except (binascii.Error, UnicodeDecodeError):
        return None

    if not decoded:
        return None

    # Strict format: "login:jwt".
    if ":" not in decoded:
        return None

    _, token = decoded.split(":", 1)
    token = token.strip()

    if not token:
        return None

    return token


def _build_public(claims: dict) -> dict:
    fn = claims.get("name") or claims.get("preferred_username", "")
    public: dict = {"fn": fn}
    photo = claims.get("picture")
    if photo:
        public["photo"] = {"type": "url", "ref": photo}
    return public


def _err(msg: str) -> TinodeResponse:
    return TinodeResponse(err=msg)


async def _verify_secret(secret: str | None) -> dict | None:
    """
    Общая точка верификации: декодирует secret (base64(login:jwt)) → JWT → claims.
    Возвращает claims-dict или None.
    Используется и в /auth, и в /link.
    """
    if not secret:
        return None
    token = _decode_secret(secret)
    if not token:
        return None
    return await verify_jwt(token)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Обязательные эндпоинты
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/auth", response_model=TinodeResponse, response_model_exclude_none=True)
async def auth_endpoint(body: TinodeRequest):
    """Аутентификация пользователя — верификация Keycloak JWT."""

    endpoint = (body.endpoint or "auth").lower()
    if endpoint != "auth":
        return _err("not found")

    claims = await _verify_secret(body.secret)
    if claims is None:
        # secret отсутствует, не base64, или JWT невалиден/просрочен
        return _err("failed")

    keycloak_id: str = claims.get("sub", "")
    if not keycloak_id:
        return _err("internal")

    preferred: str = claims.get("preferred_username", "")
    email: str = claims.get("email", "")

    # Проверяем маппинг keycloak_id → tinode_uid
    mapping = await get_by_keycloak_id(keycloak_id)

    if mapping and mapping.get("tinode_uid"):
        # Повторный вход — аккаунт уже связан
        logger.info("User %s authenticated, uid=%s", preferred, mapping["tinode_uid"])
        return TinodeResponse(
            rec=AuthRecordResponse(
                uid=mapping["tinode_uid"],
                authlvl="auth",
                features=0,
                state="ok",
            )
        )

    # Первый вход — регистрируем в локальной БД и просим Tinode создать аккаунт
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
            public=_build_public(claims),
            trusted={},
            private={},
        ),
    )


@app.post("/link", response_model=TinodeResponse, response_model_exclude_none=True)
async def link_endpoint(body: TinodeRequest):
    """
    Привязка Tinode UID к учётной записи Keycloak.

    Tinode вызывает /link сразу после создания нового аккаунта (в ответ на newacc),
    передавая тот же secret что был в /auth и свежесозданный uid.
    Мы верифицируем JWT повторно (он может быть ещё валиден) и сохраняем uid.
    """

    endpoint = (body.endpoint or "link").lower()
    if endpoint != "link":
        return _err("not found")

    if not body.rec or not body.rec.uid:
        return _err("malformed")

    claims = await _verify_secret(body.secret)
    if claims is None:
        return _err("failed")

    keycloak_id: str = claims.get("sub", "")
    if not keycloak_id:
        return _err("internal")

    preferred: str = claims.get("preferred_username", "")

    mapping = await get_by_keycloak_id(keycloak_id)
    if mapping is None:
        # Нет записи в БД — /auth не вызывался или БД рассинхронизирована
        return _err("not found")

    if mapping.get("tinode_uid"):
        # uid уже привязан — повторный /link не должен происходить
        return _err("duplicate value")

    if not await link_tinode_uid(mapping["keycloak_username"], body.rec.uid):
        return _err("internal")

    logger.info("Linked %s → tinode uid=%s", preferred, body.rec.uid)

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
    return JSONResponse(status_code=200, content={"err": "unsupported"})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Служебные эндпоинты и обработчики ошибок
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


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s\n%s", exc, traceback.format_exc())
    return JSONResponse(status_code=500, content={"err": "internal"})


@app.api_route("/{full_path:path}", methods=["POST"])
async def catch_all_post(full_path: str):
    return JSONResponse(status_code=404, content={"err": "not found"})


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=cfg.host,
        port=cfg.port,
        reload=cfg.debug,
    )