"""
Асинхронное хранилище маппинга Keycloak ↔ Tinode UID (PostgreSQL).
"""

import logging
import asyncpg

from config_example import cfg

logger = logging.getLogger("tinode-rest-auth.db")

_db_dsn = cfg.db_dsn  # например: postgres://user:pass@localhost:5432/tinode_auth

_pool: asyncpg.Pool | None = None


async def init_db() -> None:
    """Создать пул соединений и таблицу."""
    global _pool

    if _pool is not None:
        return

    pool = await asyncpg.create_pool(_db_dsn)
    try:
        async with pool.acquire() as conn:
            await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_mapping (
                keycloak_id       TEXT PRIMARY KEY,
                keycloak_username TEXT UNIQUE NOT NULL,
                tinode_uid        TEXT UNIQUE,
                created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            )
    except Exception:
        await pool.close()
        raise

    _pool = pool

    logger.info("Database initialised")


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialized")
    return _pool


async def get_by_keycloak_id(keycloak_id: str) -> dict | None:
    pool = get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM user_mapping
            WHERE keycloak_id = $1
            """,
            keycloak_id,
        )

    return dict(row) if row else None


async def get_by_username(username: str) -> dict | None:
    pool = get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM user_mapping
            WHERE keycloak_username = $1
            """,
            username,
        )

    return dict(row) if row else None


async def upsert_user(keycloak_id: str, username: str) -> None:
    pool = get_pool()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO user_mapping (keycloak_id, keycloak_username)
            VALUES ($1, $2)
            ON CONFLICT (keycloak_id) DO UPDATE
            SET keycloak_username = EXCLUDED.keycloak_username,
                updated_at = CURRENT_TIMESTAMP
            """,
            keycloak_id,
            username,
        )


async def link_tinode_uid(username: str, tinode_uid: str) -> bool:
    pool = get_pool()

    async with pool.acquire() as conn:
        try:
            result = await conn.execute(
                """
                UPDATE user_mapping
                SET tinode_uid = $1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE keycloak_username = $2
                AND tinode_uid IS NULL
                """,
                tinode_uid,
                username,
            )

            # asyncpg возвращает строку вида "UPDATE 1"
            return result.endswith("1")

        except asyncpg.UniqueViolationError:
            return False