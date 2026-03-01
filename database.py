"""
Асинхронное хранилище маппинга Keycloak ↔ Tinode UID (aiosqlite).
"""

import logging
import aiosqlite

from config_example import cfg

logger = logging.getLogger("tinode-rest-auth.db")

_db_path = cfg.db_path


async def init_db() -> None:
    """Создать таблицу, если её ещё нет."""
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
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
        await db.commit()
    logger.info("Database initialised: %s", _db_path)


async def get_by_keycloak_id(keycloak_id: str) -> dict | None:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM user_mapping WHERE keycloak_id = ?",
            (keycloak_id,),
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_by_username(username: str) -> dict | None:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM user_mapping WHERE keycloak_username = ?",
            (username,),
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def upsert_user(keycloak_id: str, username: str) -> None:
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
            """
            INSERT INTO user_mapping (keycloak_id, keycloak_username)
            VALUES (?, ?)
            ON CONFLICT(keycloak_id) DO UPDATE
                SET keycloak_username = excluded.keycloak_username,
                    updated_at        = CURRENT_TIMESTAMP
            """,
            (keycloak_id, username),
        )
        await db.commit()


async def link_tinode_uid(username: str, tinode_uid: str) -> bool:
    async with aiosqlite.connect(_db_path) as db:
        cursor = await db.execute(
            """
            UPDATE user_mapping
               SET tinode_uid = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE keycloak_username = ?
               AND tinode_uid IS NULL
            """,
            (tinode_uid, username),
        )
        await db.commit()
        return cursor.rowcount > 0