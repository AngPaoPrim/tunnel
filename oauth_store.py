import json
import os
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from typing import Any


class SQLiteMapping(MutableMapping[str, dict[str, Any]]):
    def __init__(self, database_path: str, namespace: str):
        if database_path == ":memory:":
            raise ValueError("OAuth storage must use a persistent SQLite file.")
        self.database_path = database_path
        self.namespace = namespace
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS oauth_records (
                    namespace TEXT NOT NULL,
                    record_key TEXT NOT NULL,
                    record_value TEXT NOT NULL,
                    PRIMARY KEY (namespace, record_key)
                )"""
            )
            connection.execute("PRAGMA journal_mode=WAL")
        if os.name != "nt":
            os.chmod(database_path, 0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _serialize(value: dict[str, Any]) -> str:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)

    def __getitem__(self, key: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_value FROM oauth_records "
                "WHERE namespace = ? AND record_key = ?",
                (self.namespace, key),
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row[0])

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        serialized = self._serialize(value)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO oauth_records(namespace, record_key, record_value) "
                "VALUES (?, ?, ?) ON CONFLICT(namespace, record_key) "
                "DO UPDATE SET record_value = excluded.record_value",
                (self.namespace, key, serialized),
            )

    def __delitem__(self, key: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM oauth_records WHERE namespace = ? AND record_key = ?",
                (self.namespace, key),
            )
        if cursor.rowcount == 0:
            raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_key FROM oauth_records WHERE namespace = ?",
                (self.namespace,),
            ).fetchall()
        return iter(row[0] for row in rows)

    def __len__(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM oauth_records WHERE namespace = ?",
                (self.namespace,),
            ).fetchone()
        return int(row[0])

    def pop(self, key: str, default: Any = ...):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_value FROM oauth_records "
                "WHERE namespace = ? AND record_key = ?",
                (self.namespace, key),
            ).fetchone()
            if row is None:
                if default is ...:
                    raise KeyError(key)
                return default
            connection.execute(
                "DELETE FROM oauth_records WHERE namespace = ? AND record_key = ?",
                (self.namespace, key),
            )
        return json.loads(row[0])

    def delete_if_matches(self, key: str, expected: dict[str, Any]) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM oauth_records "
                "WHERE namespace = ? AND record_key = ? AND record_value = ?",
                (self.namespace, key, self._serialize(expected)),
            )
        return cursor.rowcount == 1

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM oauth_records WHERE namespace = ?",
                (self.namespace,),
            )