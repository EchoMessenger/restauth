import asyncio
import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault(
    "asyncpg",
    types.SimpleNamespace(Pool=object, create_pool=None, UniqueViolationError=Exception),
)
sys.modules.setdefault(
    "config_example",
    types.SimpleNamespace(cfg=types.SimpleNamespace(db_dsn="postgres://user:pass@localhost/test")),
)

import database


class FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return FakeAcquire(self.conn)


class FakeConnection:
    def __init__(self, rows_by_uid):
        self.rows_by_uid = rows_by_uid
        self.requested_uids = []

    async def fetchrow(self, _query, uid):
        self.requested_uids.append(uid)
        return self.rows_by_uid.get(uid)


class TinodeUidLookupTest(unittest.TestCase):
    def test_unprefixed_uid_matches_unprefixed_column(self):
        conn = FakeConnection({
            "syn8wR750oY": {
                "keycloak_username": "peter228",
                "tinode_uid": "syn8wR750oY",
                "tinode_uid_prefixed": "usrsyn8wR750oY",
            }
        })

        with patch.object(database, "get_pool", return_value=FakePool(conn)):
            result = asyncio.run(database.get_by_tinode_uid_with_fallback("syn8wR750oY"))

        self.assertEqual(result["keycloak_username"], "peter228")
        self.assertEqual(conn.requested_uids, ["syn8wR750oY"])

    def test_prefixed_uid_falls_back_to_unprefixed_column(self):
        conn = FakeConnection({
            "syn8wR750oY": {
                "keycloak_username": "peter228",
                "tinode_uid": "syn8wR750oY",
                "tinode_uid_prefixed": "usrsyn8wR750oY",
            }
        })

        with patch.object(database, "get_pool", return_value=FakePool(conn)):
            result = asyncio.run(database.get_by_tinode_uid_with_fallback("usrsyn8wR750oY"))

        self.assertEqual(result["keycloak_username"], "peter228")
        self.assertEqual(conn.requested_uids, ["usrsyn8wR750oY", "syn8wR750oY"])


if __name__ == "__main__":
    unittest.main()
