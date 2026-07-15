"""Fixed child entry point for guarded visible-Chrome evidence collection."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Dict

from agent_flow.browser_collector import BrowserEvidenceCollector


def _contract(path_value: str) -> Dict[str, Any]:
    path = Path(path_value)
    if (
        not path.is_absolute()
        or str(path) != str(path.resolve())
        or not str(path).startswith("/private/tmp/agent-flow-")
        or path.is_symlink()
    ):
        raise ValueError("browser runtime contract path is invalid")
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_nlink != 1
        or details.st_mode & 0o077
        or details.st_size <= 0
        or details.st_size > 1024 * 1024
    ):
        raise ValueError("browser runtime contract identity is invalid")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("browser runtime contract must be an object")
    return value


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: browser_runtime.py CONTRACT_JSON")
    result = BrowserEvidenceCollector(start_new_session=False).collect(
        _contract(sys.argv[1])
    )
    sys.stdout.write(
        json.dumps(result, allow_nan=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
