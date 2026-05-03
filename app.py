import base64
import binascii
import logging
from contextlib import asynccontextmanager
import traceback

import jwt as pyjwt  # pip install PyJWT

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
    get_by_tinode_uid,
    get_by_tinode_uid_with_fallback,
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

# Системные роли Keycloak, которые не нужно проксировать в Tinode
_KEYCLOAK_SYSTEM_ROLES: frozenset[str] = frozenset(
    {
        "uma_authorization",
        "offline_access",
        "default-roles-master",
        "default-roles-realm",
        "create-realm",
        "manage-users",
        "view-users",
        "query-users",
    }
)


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
        logger.debug("Secret decode failed: invalid base64 payload")
        return None

    if not decoded:
        logger.debug("Secret decode failed: decoded payload is empty")
        return None

    # Strict format: "login:jwt".
    # Login may itself contain ':' namespace prefixes (e.g. "email:alice@example.com").
    # Split from the right to preserve the full login part.
    if ":" not in decoded:
        logger.debug("Secret decode failed: missing ':' separator")
        return None

    _, token = decoded.rsplit(":", 1)
    token = token.strip()

    if not token:
        logger.debug("Secret decode failed: JWT token is empty")
        return None

    return token


def _build_public(claims: dict) -> dict:
    fn = claims.get("name") or claims.get("preferred_username", "")
    public: dict = {"fn": fn}
    photo = claims.get("picture")
    if photo:
        public["photo"] = {"type": "url", "ref": photo}
    return public


def _extract_roles(access_token: str, client_id: str | None = None) -> list[str]:
    """
    Извлекает роли пользователя из JWT access token Keycloak.

    Собирает роли двух уровней:
      - realm_access.roles       — роли на уровне realm
      - resource_access.<client>.roles — роли конкретного клиента (если задан client_id)

    Системные роли Keycloak отфильтровываются.
    Возвращает отсортированный список уникальных бизнес-ролей.
    """
    try:
        payload = pyjwt.decode(
            access_token,
            options={"verify_signature": False},
            algorithms=["RS256", "HS256"],
        )
    except Exception as exc:
        logger.warning("Failed to decode JWT for role extraction: %s", exc)
        return []

    roles: set[str] = set()

    # Realm-level roles
    realm_roles = payload.get("realm_access", {}).get("roles", [])
    if isinstance(realm_roles, list):
        roles.update(realm_roles)

    # Client-level roles
    if client_id:
        client_roles = (
            payload.get("resource_access", {})
            .get(client_id, {})
            .get("roles", [])
        )
        if isinstance(client_roles, list):
            roles.update(client_roles)

    return sorted(roles - _KEYCLOAK_SYSTEM_ROLES)


def _build_tags(
    userinfo: dict,
    access_token: str,
    preferred: str,
    email: str,
) -> list[str]:
    """
    Формирует список тегов пользователя для Tinode.

    Теги используются для поиска пользователей и хранения метаданных:
      uname:<username>       — поиск по логину (стандартный)
      email:<addr>           — поиск по email (стандартный)
      fn:<given_name>        — поиск по имени
      fn:<family_name>       — поиск по фамилии
      fn:<given family>      — поиск по полному имени
      role:<role_name>       — роль пользователя из Keycloak

    Теги `role:*` должны быть добавлены в restricted_tag_ns (см. /rtagns),
    чтобы пользователи не могли назначать их себе самостоятельно.
    """
    tags: list[str] = [f"uname:{preferred}"]

    if email:
        tags.append(f"email:{email}")

    # ФИ — отдельные теги для поиска по имени, фамилии и полному имени
    given_name: str = userinfo.get("given_name", "").strip()
    family_name: str = userinfo.get("family_name", "").strip()
    full_name: str = userinfo.get("name", "").strip()

    if given_name:
        tags.append(f"fn:{given_name}")
    if family_name:
        tags.append(f"fn:{family_name}")
    # Полное имя — только если отличается от отдельных частей и не пусто
    if full_name and full_name not in (given_name, family_name):
        tags.append(f"fn:{full_name}")

    # Роли из Keycloak JWT
    roles = _extract_roles(access_token, getattr(cfg, "keycloak_client_id", None))
    for role in roles:
        tags.append(f"role:{role}")

    logger.debug("Built tags for %s: %s", preferred, tags)
    return tags


def _err(msg: str) -> TinodeResponse:
    return TinodeResponse(err=msg)


def _secret_meta(secret: str | None) -> str:
    if not secret:
        return "none"
    return f"len={len(secret)}"


def _claims_meta(claims: dict | None) -> str:
    if not claims:
        return "none"
    sub = claims.get("sub", "")
    preferred = claims.get("preferred_username", "")
    exp = claims.get("exp")
    return f"sub={sub} preferred={preferred} exp={exp}"


async def _verify_secret(secret: str | None) -> dict | None:
    """
    Общая точка верификации: декодирует secret (base64(login:jwt)) → JWT → claims.
    Возвращает claims-dict или None.
    Используется и в /auth, и в /link.
    """
    if not secret:
        logger.debug("Secret verification failed: secret is missing")
        return None
    token = _decode_secret(secret)
    if not token:
        logger.debug("Secret verification failed: cannot decode JWT from secret")
        return None
    claims = await verify_jwt(token)
    if claims is None:
        logger.debug("Secret verification failed: JWT validation returned no claims")
    else:
        logger.debug("Secret verified successfully: %s", _claims_meta(claims))
    return claims


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Обязательные эндпоинты
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/auth", response_model=TinodeResponse, response_model_exclude_none=True)
async def auth_endpoint(body: TinodeRequest):
    """Аутентификация пользователя — верификация Keycloak JWT."""

    endpoint = (body.endpoint or "auth").lower()
    logger.info(
        "AUTH request received endpoint=%s has_secret=%s rec_uid=%s",
        endpoint,
        bool(body.secret),
        body.rec.uid if body.rec else None,
    )
    if endpoint != "auth":
        logger.warning("AUTH rejected: unexpected endpoint=%s", endpoint)
        return _err("not found")

    claims = await _verify_secret(body.secret)
    if claims is None:
        # secret отсутствует, не base64, или JWT невалиден/просрочен
        logger.warning("AUTH failed: secret verification failed (%s)", _secret_meta(body.secret))
        return _err("failed")

    keycloak_id: str = claims.get("sub", "")
    if not keycloak_id:
        logger.error("AUTH failed: JWT has no 'sub' claim (%s)", _claims_meta(claims))
        return _err("internal")

    preferred: str = claims.get("preferred_username", "")
    email: str = claims.get("email", "")
    display_name: str = claims.get("name") or preferred

    keycloak_id = userinfo.get("sub")
    if not isinstance(keycloak_id, str) or not keycloak_id:
        return _err("internal")

    email: str = userinfo.get("email", "")
    preferred: str = userinfo.get("preferred_username", username)

    # 3. Теги формируем всегда — они могут измениться (новая роль, смена имени)
    tags = _build_tags(userinfo, access_token, preferred, email)

    # 4. Проверяем маппинг
    mapping = await get_by_keycloak_id(keycloak_id)

    if mapping and mapping.get("tinode_uid"):
        # Повторный вход — аккаунт уже связан
        logger.info(
            "AUTH success existing user preferred=%s keycloak_id=%s uid=%s",
            preferred,
            keycloak_id,
            mapping["tinode_uid"],
        )
        return TinodeResponse(
            rec=AuthRecordResponse(
                uid=mapping["tinode_uid"],
                authlvl="auth",
                tags=tags,
                features=0,
                state="ok",
            )
        )

    # Первый вход — регистрируем в локальной БД и просим Tinode создать аккаунт
    await upsert_user(keycloak_id, preferred, display_name=display_name, email=email or None)

    logger.info(
        "AUTH success first login preferred=%s keycloak_id=%s tags=%s",
        preferred,
        keycloak_id,
        tags,
    )

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
    logger.info(
        "LINK request received endpoint=%s rec_uid=%s has_secret=%s",
        endpoint,
        body.rec.uid if body.rec else None,
        bool(body.secret),
    )
    if endpoint != "link":
        logger.warning("LINK rejected: unexpected endpoint=%s", endpoint)
        return _err("not found")

    if not body.rec or not body.rec.uid:
        logger.warning("LINK failed: missing rec.uid")
        return _err("malformed")

    claims = await _verify_secret(body.secret)
    if claims is None:
        logger.warning("LINK failed: secret verification failed (%s)", _secret_meta(body.secret))
        return _err("failed")

    keycloak_id: str = claims.get("sub", "")
    if not keycloak_id:
        logger.error("LINK failed: JWT has no 'sub' claim (%s)", _claims_meta(claims))
        return _err("internal")

    preferred: str = claims.get("preferred_username", "")

    mapping = await get_by_keycloak_id(keycloak_id)
    if mapping is None:
        # Нет записи в БД — /auth не вызывался или БД рассинхронизирована
        logger.warning(
            "LINK failed: no local mapping for keycloak_id=%s preferred=%s uid=%s",
            keycloak_id,
            preferred,
            body.rec.uid,
        )
        return _err("not found")

    if mapping.get("tinode_uid"):
        # uid уже привязан — повторный /link не должен происходить
        logger.warning(
            "LINK duplicate: keycloak_id=%s already linked_uid=%s new_uid=%s",
            keycloak_id,
            mapping.get("tinode_uid"),
            body.rec.uid,
        )
        return _err("duplicate value")

    if not await link_tinode_uid(mapping["keycloak_username"], body.rec.uid):
        logger.error(
            "LINK failed: database update failed for keycloak_username=%s uid=%s",
            mapping["keycloak_username"],
            body.rec.uid,
        )
        return _err("internal")

    logger.info(
        "LINK success preferred=%s keycloak_id=%s keycloak_username=%s uid=%s",
        preferred,
        keycloak_id,
        mapping["keycloak_username"],
        body.rec.uid,
    )

    # Успех — пустой JSON-объект
    return TinodeResponse()


@app.post("/rtagns", response_model=TinodeResponse, response_model_exclude_none=True)
async def rtagns_endpoint():
    """
    Список restricted tag namespaces.

    Неймспейс `role` добавлен в restricted, чтобы пользователи
    не могли назначать роли себе напрямую через Tinode-клиент.
    Управление ролями — исключительно через Keycloak.
    """
    restricted = list(cfg.restricted_tag_ns)
    if "role" not in restricted:
        restricted.append("role")

    return TinodeResponse(
        strarr=restricted,
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


@app.get("/users/by-tinode-uid/{tinode_uid}")
async def get_user_by_tinode_uid(tinode_uid: str):
    """
    Служебный endpoint для внутренних сервисов (например, audit):
    резолвит Tinode UID → Keycloak username/displayName.

    Supports both prefixed ('usr123') and unprefixed ('123') tinode_uid formats
    for backward compatibility.
    """
    logger.debug("Lookup by Tinode UID requested uid=%s", tinode_uid)
    mapping = await get_by_tinode_uid_with_fallback(tinode_uid)
    if mapping is None:
        logger.info("Lookup by Tinode UID not found uid=%s", tinode_uid)
        return JSONResponse(status_code=404, content={"err": "not found"})

    logger.info(
        "Lookup by Tinode UID success uid=%s keycloak_id=%s keycloak_username=%s",
        tinode_uid,
        mapping.get("keycloak_id"),
        mapping.get("keycloak_username"),
    )

    return {
        "tinodeUid": mapping.get("tinode_uid"),
        "keycloakId": mapping.get("keycloak_id"),
        "keycloakUsername": mapping.get("keycloak_username"),
        "displayName": mapping.get("display_name") or mapping.get("keycloak_username"),
        "email": mapping.get("email"),
    }


@app.exception_handler(404)
async def handle_404(request: Request, exc):
    logger.debug("HTTP 404 path=%s", request.url.path)
    return JSONResponse(status_code=404, content={"err": "not found"})


@app.exception_handler(405)
async def handle_405(request: Request, exc):
    logger.debug("HTTP 405 path=%s method=%s", request.url.path, request.method)
    return JSONResponse(status_code=405, content={"err": "method not allowed"})


@app.exception_handler(500)
async def handle_500(request: Request, exc):
    logger.error("HTTP 500 handler path=%s exc=%s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"err": "internal"})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception path=%s: %s\n%s", request.url.path, exc, traceback.format_exc())
    return JSONResponse(status_code=500, content={"err": "internal"})


@app.api_route("/{full_path:path}", methods=["POST"])
async def catch_all_post(full_path: str):
    logger.debug("Unknown POST path=%s", full_path)
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