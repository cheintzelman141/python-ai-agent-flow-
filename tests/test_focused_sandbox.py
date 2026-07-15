from __future__ import annotations

import errno
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, Tuple

import pytest

from agent_flow.focused_sandbox import (
    DARWIN_SANDBOX_POLICY_VERSION,
    FocusedSandboxError,
    build_command,
    build_profile,
    direct_python_executable,
    profile_sha256,
    python_runtime_root,
    python_runtime_sha256,
    sandbox_executable,
)


def _sandbox_layout(tmp_path: Path) -> Tuple[Path, Path, Path, Path, str]:
    workspace = tmp_path / "workspace"
    run_parent = tmp_path / "runtime" / "attempt"
    workspace.mkdir()
    run_parent.mkdir(parents=True)
    (run_parent / "environment" / "home").mkdir(parents=True)
    (run_parent / "environment" / "tmp").mkdir()
    executable = direct_python_executable(Path(sys.executable))
    runtime_root = python_runtime_root(executable)
    profile = build_profile(
        test_executable=executable,
        runtime_read_root=runtime_root,
        workspace=workspace,
        run_parent=run_parent,
    )
    return workspace, run_parent, executable, runtime_root, profile


def test_profile_and_launch_command_are_byte_stable_and_narrow(
    tmp_path: Path,
) -> None:
    workspace, run_parent, executable, runtime_root, first = _sandbox_layout(tmp_path)
    second = build_profile(
        test_executable=executable,
        runtime_read_root=runtime_root,
        workspace=workspace,
        run_parent=run_parent,
    )
    test_command = (str(executable), "-I", "-B", str(workspace / "test.py"))
    command = build_command(sandbox_executable(), first, test_command)

    assert DARWIN_SANDBOX_POLICY_VERSION == "darwin-seatbelt-v1"
    assert first == second
    assert profile_sha256(first) == profile_sha256(second)
    assert python_runtime_sha256(runtime_root) == python_runtime_sha256(runtime_root)
    assert first.startswith("(version 1)\n(deny default)\n")
    assert "(deny file-read-data\n" in first
    assert '(subpath "%s")' % workspace in first
    assert '(subpath "%s")' % run_parent in first
    assert "network" not in first
    assert "process-fork" not in first
    assert command == (str(sandbox_executable()), "-p", first, *test_command)


def test_user_owned_python_runtime_is_not_trusted(tmp_path: Path) -> None:
    executable = tmp_path / "runtime" / "bin" / "python"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"not-a-trusted-runtime")
    executable.chmod(0o755)

    with pytest.raises(FocusedSandboxError, match="root-owned and immutable"):
        python_runtime_root(executable)


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS Seatbelt")
def test_real_seatbelt_denies_filesystem_network_and_child_escape(
    tmp_path: Path,
) -> None:
    workspace, run_parent, executable, _runtime_root, profile = _sandbox_layout(
        tmp_path
    )
    outside_secret = tmp_path / "outside-secret.txt"
    outside_secret.write_text("not-authorized\n", encoding="utf-8")
    outside_write = tmp_path / "outside-write.txt"
    workspace_write = workspace / "workspace-write.txt"
    detached_marker = run_parent / "environment" / "home" / "detached.txt"
    probe = workspace / "probe.py"
    probe.write_text(
        """import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

OUTSIDE_SECRET = Path(%r)
OUTSIDE_WRITE = Path(%r)
WORKSPACE_WRITE = Path(%r)
LIST_PARENT = Path(%r)
LIST_HOME = Path(%r)
DETACHED_MARKER = Path(%r)

def observe(operation):
    try:
        value = operation()
        return {"allowed": True, "value": value}
    except BaseException as error:
        return {
            "allowed": False,
            "type": type(error).__name__,
            "errno": getattr(error, "errno", None),
        }

def connect_loopback():
    connection = socket.socket()
    connection.settimeout(0.2)
    try:
        connection.connect(("127.0.0.1", 9))
        return "connected"
    finally:
        connection.close()

def fork_process():
    child = os.fork()
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)
    return child

def run_subprocess():
    return subprocess.run(["/bin/echo", "escaped"], check=False).returncode

def start_detached():
    child = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c",
         "from pathlib import Path; Path(%r).write_text('escaped')"],
        start_new_session=True,
    )
    return child.wait(timeout=1)

def read_symlink_escape():
    link = Path(os.environ["HOME"]) / "outside-read-link"
    link.symlink_to(OUTSIDE_SECRET)
    return link.read_text()

def write_symlink_escape():
    link = Path(os.environ["HOME"]) / "outside-write-link"
    link.symlink_to(OUTSIDE_WRITE)
    return link.write_text("escaped")

def hardlink_escape():
    link = Path(os.environ["HOME"]) / "outside-hardlink"
    os.link(OUTSIDE_SECRET, link)
    return link.read_text()

scratch = Path(os.environ["HOME"]) / "allowed.txt"
results = {
    "import_unittest": observe(lambda: __import__("unittest").__name__),
    "workspace_read": observe(lambda: Path(__file__).read_text()),
    "scratch_write": observe(lambda: scratch.write_text("allowed")),
    "outside_read": observe(lambda: OUTSIDE_SECRET.read_text()),
    "outside_write": observe(lambda: OUTSIDE_WRITE.write_text("escaped")),
    "workspace_write": observe(lambda: WORKSPACE_WRITE.write_text("escaped")),
    "list_parent": observe(lambda: sorted(path.name for path in LIST_PARENT.iterdir())),
    "list_home": observe(lambda: sorted(path.name for path in LIST_HOME.iterdir())),
    "list_tmp_alias": observe(lambda: sorted(path.name for path in Path("/tmp").iterdir())),
    "symlink_read": observe(read_symlink_escape),
    "symlink_write": observe(write_symlink_escape),
    "hardlink": observe(hardlink_escape),
    "network": observe(connect_loopback),
    "fork": observe(fork_process),
    "subprocess": observe(run_subprocess),
    "detached": observe(start_detached),
}
print(json.dumps(results, sort_keys=True))
"""
        % (
            str(outside_secret),
            str(outside_write),
            str(workspace_write),
            str(tmp_path),
            str(Path.home()),
            str(detached_marker),
            str(detached_marker),
        ),
        encoding="utf-8",
    )
    test_command = (str(executable), "-I", "-B", str(probe))
    command = build_command(sandbox_executable(), profile, test_command)
    environment = {
        "HOME": str(run_parent / "environment" / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TMPDIR": str(run_parent / "environment" / "tmp"),
    }

    completed = subprocess.run(
        command,
        cwd=str(workspace),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr
    results: Dict[str, Dict[str, Any]] = json.loads(completed.stdout)
    assert results["import_unittest"] == {"allowed": True, "value": "unittest"}
    assert results["workspace_read"]["allowed"] is True
    assert results["scratch_write"]["allowed"] is True
    for control in (
        "outside_read",
        "outside_write",
        "workspace_write",
        "list_parent",
        "list_home",
        "list_tmp_alias",
        "symlink_read",
        "symlink_write",
        "hardlink",
        "network",
        "fork",
        "subprocess",
        "detached",
    ):
        assert results[control]["allowed"] is False, (control, results[control])
        assert results[control]["type"] == "PermissionError"
        assert results[control]["errno"] == errno.EPERM
    time.sleep(0.1)
    assert (run_parent / "environment" / "home" / "allowed.txt").read_text() == (
        "allowed"
    )
    assert not outside_write.exists()
    assert not workspace_write.exists()
    assert not detached_marker.exists()
