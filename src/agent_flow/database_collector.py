"""Trusted, fixed-plan read-only SQLite evidence collection.

The collector accepts only a storage-prepared contract.  It never accepts SQL,
credentials, paths, or limits from worker output and writes one bounded,
canonical result artifact at the exact prepared path.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Dict, Mapping, Optional, Sequence


class DatabaseCollectorError(RuntimeError):
    """A sanitized fixed database collection failure."""


_ENVIRONMENT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SELECT = re.compile(r"SELECT\b", re.IGNORECASE)


def _direct_select(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not _SELECT.match(value)
        or any(marker in value for marker in (";", "--", "/*", "*/", "#", "\x00"))
    ):
        raise DatabaseCollectorError("prepared database statement is not one direct SELECT")
    return value


def _bounded_scalars(value: Any) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)) or len(value) > 64:
        raise DatabaseCollectorError("prepared database parameters are invalid")
    for parameter in value:
        if parameter is not None and not isinstance(
            parameter, (str, int, float, bool)
        ):
            raise DatabaseCollectorError("prepared database parameters are invalid")
        if isinstance(parameter, float) and not math.isfinite(parameter):
            raise DatabaseCollectorError("prepared database parameters are invalid")
    return tuple(value)


class DatabaseEvidenceCollector:
    """Execute one exact supervisor-owned SELECT against disposable SQLite."""

    def collect(
        self,
        contract: Mapping[str, Any],
        *,
        environment: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, str]:
        try:
            return self._collect(contract, os.environ if environment is None else environment)
        except DatabaseCollectorError:
            raise
        except BaseException as error:
            raise DatabaseCollectorError(
                "fixed read-only database collection failed"
            ) from error

    def _collect(
        self, contract: Mapping[str, Any], environment: Mapping[str, str]
    ) -> Dict[str, str]:
        execution_id = contract.get("id")
        result_path_value = contract.get("result_path")
        configuration = contract.get("database_configuration")
        if (
            not isinstance(execution_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", execution_id) is None
            or not isinstance(result_path_value, str)
            or not isinstance(configuration, Mapping)
        ):
            raise DatabaseCollectorError("prepared database contract is incomplete")
        statement = _direct_select(contract.get("statement"))
        parameters = _bounded_scalars(contract.get("parameters"))
        max_rows = contract.get("max_rows")
        max_bytes = contract.get("max_bytes")
        timeout_seconds = contract.get("timeout_seconds")
        if (
            not isinstance(max_rows, int)
            or isinstance(max_rows, bool)
            or not 1 <= max_rows <= 1000
            or not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 1024 <= max_bytes <= 16 * 1024 * 1024
            or not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= 60
        ):
            raise DatabaseCollectorError("prepared database limits are invalid")
        connection_env = configuration.get("connection_env")
        database_name = configuration.get("database_name")
        if (
            not isinstance(connection_env, str)
            or _ENVIRONMENT_KEY.fullmatch(connection_env) is None
            or not isinstance(database_name, str)
            or not database_name
        ):
            raise DatabaseCollectorError("prepared database resource is invalid")
        database_path_value = environment.get(connection_env)
        if not isinstance(database_path_value, str) or not database_path_value:
            raise DatabaseCollectorError("database credential reference is unavailable")
        database_path = Path(database_path_value).expanduser()
        if (
            not database_path.is_absolute()
            or str(database_path) != str(database_path.resolve())
            or not str(database_path).startswith("/private/tmp/agent-flow-")
            or database_path.stem != database_name
            or database_path.is_symlink()
        ):
            raise DatabaseCollectorError("database credential reference is not disposable SQLite")
        try:
            database_details = database_path.lstat()
        except OSError as error:
            raise DatabaseCollectorError("disposable database is unavailable") from error
        if (
            not stat.S_ISREG(database_details.st_mode)
            or database_details.st_uid != os.getuid()
            or database_details.st_nlink != 1
            or database_details.st_mode & 0o077
        ):
            raise DatabaseCollectorError("disposable database identity is invalid")
        database_parent = database_path.parent.lstat()
        if (
            not stat.S_ISDIR(database_parent.st_mode)
            or database_parent.st_uid != os.getuid()
            or database_parent.st_mode & 0o077
        ):
            raise DatabaseCollectorError(
                "disposable database directory is not private"
            )
        result_path = Path(result_path_value)
        if (
            not result_path.is_absolute()
            or str(result_path) != str(result_path.resolve())
            or not str(result_path).startswith("/private/tmp/agent-flow-")
            or result_path.name != "result.json"
            or result_path.exists()
            or result_path.is_symlink()
        ):
            raise DatabaseCollectorError("prepared database artifact path is invalid")
        parent = result_path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077
        ):
            raise DatabaseCollectorError("prepared database artifact directory is not private")

        connection = sqlite3.connect(
            database_path.as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=min(float(timeout_seconds), 5.0),
        )
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            connection.set_progress_handler(
                lambda: 1 if time.monotonic() >= deadline else 0,
                1000,
            )
            connection.execute("PRAGMA query_only = ON")
            query_only = connection.execute("PRAGMA query_only").fetchone()[0] == 1
            foreign_key_violations = (
                0
                if connection.execute("PRAGMA foreign_key_check").fetchone()
                is None
                else 1
            )
            allowed_actions = {
                sqlite3.SQLITE_READ,
                sqlite3.SQLITE_SELECT,
            }
            recursive = getattr(sqlite3, "SQLITE_RECURSIVE", None)
            if recursive is not None:
                allowed_actions.add(recursive)

            def authorize(
                action: int,
                _first: Optional[str],
                _second: Optional[str],
                _database: Optional[str],
                _trigger: Optional[str],
            ) -> int:
                return (
                    sqlite3.SQLITE_OK
                    if action in allowed_actions
                    else sqlite3.SQLITE_DENY
                )

            connection.set_authorizer(authorize)
            cursor = connection.execute(statement, parameters)
            rows = cursor.fetchmany(max_rows + 1)
            if len(rows) > max_rows:
                raise DatabaseCollectorError("database result exceeded its row bound")
            columns = [str(column[0]) for column in (cursor.description or ())]
            payload = {
                "columns": columns,
                "read_only_proof": {
                    "authorizer": "deny_non_read",
                    "foreign_key_violations": foreign_key_violations,
                    "query_only": query_only,
                    "uri_mode": "ro",
                },
                "rows": [list(row) for row in rows],
            }
            raw = json.dumps(
                payload,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if not raw or len(raw) > max_bytes:
                raise DatabaseCollectorError("database result exceeded its byte bound")
            with result_path.open("xb") as artifact:
                os.chmod(result_path, 0o600)
                artifact.write(raw)
                artifact.flush()
                os.fsync(artifact.fileno())
            digest = hashlib.sha256(raw).hexdigest()
            if _SHA256.fullmatch(digest) is None:
                raise DatabaseCollectorError("database artifact hash is invalid")
            return {
                "execution_id": execution_id,
                "result_path": str(result_path),
                "result_sha256": digest,
            }
        except sqlite3.Error as error:
            raise DatabaseCollectorError(
                "fixed read-only database query was rejected"
            ) from error
        finally:
            connection.close()
