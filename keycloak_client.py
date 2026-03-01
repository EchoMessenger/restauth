"""
Асинхронный клиент Keycloak (httpx).
"""

import logging
import httpx

from config_example import cfg

logger = logging.getLogger("tinode-rest-auth.keycloak")

_TIMEOUT = 10.0


async def authenticate(username: str, password: str) -> dict | None:
    """
    Resource Owner Password Credentials grant.
    Возвращает token response или None.
    """
    payload = {
        "grant_type": "password",
        "client_id": cfg.keycloak_client_id,
        "username": username,
        "password": password,
    }
    if cfg.keycloak_client_secret:
        payload["client_secret"] = cfg.keycloak_client_secret

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.post(cfg.token_url, data=payload)
        except httpx.RequestError:
            logger.exception("Keycloak token request failed")
            return None

    if resp.status_code == 200:
        return resp.json()

    logger.warning(
        "Keycloak auth failed: status=%s body=%s",
        resp.status_code,
        resp.text[:300],
    )
    return None


async def get_userinfo(access_token: str) -> dict | None:
    """Получить профиль через UserInfo endpoint."""
    headers = {"Authorization": f"Bearer {access_token}"}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(cfg.userinfo_url, headers=headers)
        except httpx.RequestError:
            logger.exception("Keycloak userinfo request failed")
            return None

    if resp.status_code == 200:
        return resp.json()

    logger.warning(
        "Keycloak userinfo failed: status=%s body=%s",
        resp.status_code,
        resp.text[:300],
    )
    return None