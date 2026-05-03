"""
Асинхронный клиент Keycloak — верификация JWT через JWKS.

Flow:
  1. При первом обращении (или при kid-mismatch) скачиваем JWKS
     с /realms/{realm}/protocol/openid-connect/certs и кешируем.
  2. Верифицируем подпись, exp, iss, aud локально через PyJWT.
  3. Возвращаем dict с claims или None при любой ошибке.
"""

import asyncio
import logging
from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKClientError, DecodeError, ExpiredSignatureError, InvalidTokenError

from config_example import cfg

logger = logging.getLogger("tinode-rest-auth.keycloak")

_TIMEOUT = 10.0
_JWKS_TTL = 3600  # секунды до принудительного обновления кеша

# ── JWKS-кеш ─────────────────────────────────────────────────
# PyJWT's PyJWKClient сам умеет кешировать и обновлять ключи,
# поэтому держим один instance на весь процесс.
# lifespan_in_seconds задаёт TTL встроенного кеша.
_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            cfg.jwks_url,
            lifespan=_JWKS_TTL,
            timeout=_TIMEOUT,
        )
    return _jwks_client


def _audience_matches(claims: dict[str, Any]) -> bool:
    expected = cfg.keycloak_client_id
    aud = claims.get("aud")
    azp = claims.get("azp")

    if isinstance(aud, str):
        if aud == expected:
            return True
    elif isinstance(aud, list):
        if expected in aud:
            return True

    if isinstance(azp, str) and azp == expected:
        return True

    return False


# ── Публичный API ─────────────────────────────────────────────


async def verify_jwt(token: str) -> dict[str, Any] | None:
    """
    Верифицирует Keycloak access-token и возвращает его claims.

    Проверяет:
      - подпись (RSA/ECDSA ключ из JWKS);
      - срок действия (exp);
      - issuer (iss == keycloak_url/realms/realm);
      - audience (aud содержит keycloak_client_id).

    Возвращает dict с claims или None при любой ошибке.
    """
    client = _get_jwks_client()
    expected_issuer = (
        f"{cfg.normalized_keycloak_url}/realms/{cfg.keycloak_realm}"
    )

    try:
        # Получаем подписывающий ключ (обновляет кеш при kid-mismatch)
        loop = asyncio.get_running_loop()
        signing_key = await loop.run_in_executor(
            None,
            client.get_signing_key_from_jwt,
            token,
        )
    except PyJWKClientError:
        logger.warning("JWKS: не удалось получить ключ для токена")
        return None
    except DecodeError as exc:
        logger.warning("JWKS: ошибка декодирования токена — %s", exc)
        return None

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            issuer=expected_issuer,
            options={"require": ["exp", "iat", "sub"], "verify_aud": False},
        )
    except ExpiredSignatureError:
        logger.warning("JWT: токен просрочен")
        return None
    except DecodeError as exc:
        logger.warning("JWT: ошибка декодирования — %s", exc)
        return None
    except InvalidTokenError as exc:
        logger.warning("JWT: невалидный токен — %s", exc)
        return None

    if not _audience_matches(claims):
        logger.warning(
            "JWT: невалидный токен — Audience doesn't match (aud=%s azp=%s expected=%s)",
            claims.get("aud"),
            claims.get("azp"),
            cfg.keycloak_client_id,
        )
        return None

    return claims