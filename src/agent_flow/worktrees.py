"""Durable, fail-closed Git worktree lifecycle management.

SQLite owns intent, fencing, identity, and state transitions.  This module
performs bounded Git and filesystem work outside database transactions.  Git
mutations use a blocked guardian so the exact process identity is durable
before the Git executable can start.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    BinaryIO,
    Callable,
    ContextManager,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from agent_flow.process_reconciler import (
    DarwinProcessRuntime,
    ExternalProcessBinding,
    ExternalProcessReconciler,
    ProcessIdentity,
    ProcessInspectionError,
    ProcessRuntime,
    ReconciliationResult,
    ReconciliationStatus,
)
from agent_flow.storage import SQLiteStore


_GIT_CONFIG_OVERRIDES = (
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.untrackedCache=false",
    "core.sparseCheckout=false",
    "core.sparseCheckoutCone=false",
)
_GUARDED_LAUNCHER = """\
import os
import signal
import subprocess
import sys

barrier_fd = int(sys.argv[1])
status_fd = int(sys.argv[2])
control_fd = int(sys.argv[3])
try:
    release = os.read(barrier_fd, 1)
finally:
    os.close(barrier_fd)
if release != b"1":
    raise SystemExit(125)
command = sys.argv[4:]
signal.signal(signal.SIGTERM, lambda _signum, _frame: None)
child = subprocess.Popen(command, stdin=subprocess.DEVNULL)
return_code = child.wait()
try:
    os.write(status_fd, (str(return_code) + "\\n").encode("ascii"))
finally:
    os.close(status_fd)
devnull = os.open(os.devnull, os.O_WRONLY)
try:
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
finally:
    os.close(devnull)
try:
    os.read(control_fd, 1)
finally:
    os.close(control_fd)
raise SystemExit(return_code)
"""
_GIT_REMOVE_SEQUENCE = """\
import json
import subprocess
import sys

for payload in sys.argv[1:]:
    result = subprocess.run(json.loads(payload), check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
raise SystemExit(0)
"""


class ManagedWorktreeError(RuntimeError):
    """The worktree lifecycle could not be proven safe."""


class GitCommandError(ManagedWorktreeError):
    """A bounded Git command failed or timed out."""

    def __init__(
        self,
        message: str,
        *,
        result: Optional["GuardedCommandResult"] = None,
    ) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class ManagedWorktreeConfig:
    worktree_root: Path = Path.home() / ".agent-flow" / "worktrees"
    runtime_root: Path = Path("/private/tmp/agent-flow-worktree-runtime")
    command_timeout_seconds: float = 300.0
    terminate_grace_seconds: float = 5.0
    operation_lease_seconds: float = 900.0
    max_output_bytes: int = 2 * 1024 * 1024
    environment_overrides: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.worktree_root.is_absolute() or not self.runtime_root.is_absolute():
            raise ValueError("worktree and runtime roots must be absolute")
        if (
            self.command_timeout_seconds <= 0
            or self.terminate_grace_seconds <= 0
            or self.operation_lease_seconds <= 0
        ):
            raise ValueError("worktree lifecycle timeouts must be positive")
        if self.operation_lease_seconds <= self.command_timeout_seconds:
            raise ValueError("operation lease must outlast the Git command timeout")
        if self.max_output_bytes < 1024:
            raise ValueError("worktree command output limit must be at least 1024 bytes")


@dataclass(frozen=True)
class GuardedCommandResult:
    command: Tuple[str, ...]
    return_code: int
    stdout_path: Path
    stderr_path: Path
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool


class _CaptureThread:
    def __init__(self, stream: BinaryIO, path: Path, limit: int) -> None:
        self.stream = stream
        self.path = path
        self.limit = limit
        self.digest = hashlib.sha256()
        self.total = 0
        self.written = 0
        self.error: Optional[BaseException] = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    @property
    def truncated(self) -> bool:
        return self.total > self.limit

    def start(self) -> None:
        self.thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise GitCommandError("guarded command capture did not finish")
        if self.error is not None:
            raise GitCommandError("guarded command capture failed") from self.error

    def _run(self) -> None:
        try:
            with self.path.open("xb") as output:
                os.chmod(self.path, 0o600)
                while True:
                    chunk = self.stream.read(64 * 1024)
                    if not chunk:
                        break
                    self.total += len(chunk)
                    remaining = self.limit - self.written
                    if remaining > 0:
                        retained = chunk[:remaining]
                        output.write(retained)
                        self.digest.update(retained)
                        self.written += len(retained)
        except BaseException as error:
            self.error = error
        finally:
            self.stream.close()


class GuardedGitCommandRunner:
    """Run one Git mutation only after its guardian identity is persisted."""

    def __init__(
        self,
        *,
        runtime: ProcessRuntime,
        timeout_seconds: float,
        terminate_grace_seconds: float,
        max_output_bytes: int,
    ) -> None:
        self.runtime = runtime
        self.timeout_seconds = timeout_seconds
        self.terminate_grace_seconds = terminate_grace_seconds
        self.max_output_bytes = max_output_bytes

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        artifact_directory: Path,
        record_process: Callable[[ProcessIdentity, str], None],
        clear_process: Callable[[int, int], None],
        release_fence: Optional[
            Callable[[ProcessIdentity, str], ContextManager[None]]
        ] = None,
        cancellation_event: Optional[threading.Event] = None,
    ) -> GuardedCommandResult:
        if not command or not Path(command[0]).is_absolute():
            raise ValueError("guarded command requires an absolute executable")
        artifact_directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.chmod(artifact_directory, 0o700)
        stdout_path = artifact_directory / "stdout.log"
        stderr_path = artifact_directory / "stderr.log"
        barrier_read_fd, barrier_write_fd = os.pipe()
        status_read_fd, status_write_fd = os.pipe()
        control_read_fd, control_write_fd = os.pipe()
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _GUARDED_LAUNCHER,
                    str(barrier_read_fd),
                    str(status_write_fd),
                    str(control_read_fd),
                    *command,
                ],
                cwd=str(cwd),
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=(barrier_read_fd, status_write_fd, control_read_fd),
            )
        except BaseException:
            for descriptor in (
                barrier_read_fd,
                barrier_write_fd,
                status_read_fd,
                status_write_fd,
                control_read_fd,
                control_write_fd,
            ):
                self._close_fd(descriptor)
            raise
        self._close_fd(barrier_read_fd)
        self._close_fd(status_write_fd)
        self._close_fd(control_read_fd)
        assert process.stdout is not None
        assert process.stderr is not None

        try:
            identity = self._inspect_stable_guardian(process.pid)
            record_process(identity, str(Path(command[0]).resolve()))
        except BaseException:
            self._close_fd(barrier_write_fd)
            self._close_fd(status_read_fd)
            self._close_fd(control_write_fd)
            self._wait_or_kill_unreleased(process)
            raise

        cancelled_before_release = bool(
            cancellation_event is not None and cancellation_event.is_set()
        )

        stdout_capture = _CaptureThread(
            process.stdout, stdout_path, self.max_output_bytes
        )
        stderr_capture = _CaptureThread(
            process.stderr, stderr_path, self.max_output_bytes
        )
        stdout_capture.start()
        stderr_capture.start()
        status: Dict[str, Any] = {}

        def read_status() -> None:
            try:
                payload = bytearray()
                while len(payload) <= 32 and b"\n" not in payload:
                    chunk = os.read(status_read_fd, 32 - len(payload))
                    if not chunk:
                        break
                    payload.extend(chunk)
                status["return_code"] = int(bytes(payload).strip())
            except BaseException as error:
                status["error"] = error
            finally:
                self._close_fd(status_read_fd)

        status_thread = threading.Thread(target=read_status, daemon=True)
        status_thread.start()
        release_error: Optional[BaseException] = None
        cancelled_before_release = cancelled_before_release or bool(
            cancellation_event is not None and cancellation_event.is_set()
        )
        try:
            if cancelled_before_release:
                self._close_fd(barrier_write_fd)
            elif release_fence is None:
                os.write(barrier_write_fd, b"1")
            else:
                # The storage transaction remains open across this exact write.
                # Admission revocation and guardian release therefore have one
                # durable serialization order instead of a check-then-release gap.
                with release_fence(identity, str(Path(command[0]).resolve())):
                    if cancellation_event is not None and cancellation_event.is_set():
                        cancelled_before_release = True
                    else:
                        os.write(barrier_write_fd, b"1")
        except BaseException as error:
            release_error = error
        finally:
            self._close_fd(barrier_write_fd)

        if release_error is not None or cancelled_before_release:
            try:
                process.wait(timeout=self.terminate_grace_seconds)
                if not self._wait_for_group_exit(identity.process_group_id):
                    raise ManagedWorktreeError(
                        "Git process group remained after guardian release failed"
                    )
            except subprocess.TimeoutExpired:
                self._terminate_guardian(
                    process, identity, control_write_fd, child_completed=False
                )
            finally:
                self._close_fd(control_write_fd)
            status_thread.join(self.terminate_grace_seconds)
            stdout_capture.join(self.terminate_grace_seconds)
            stderr_capture.join(self.terminate_grace_seconds)
            clear_process(identity.process_id, identity.process_group_id)
            result = GuardedCommandResult(
                command=tuple(command),
                return_code=-1,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                stdout_sha256=stdout_capture.digest.hexdigest(),
                stderr_sha256=stderr_capture.digest.hexdigest(),
                stdout_truncated=stdout_capture.truncated,
                stderr_truncated=stderr_capture.truncated,
            )
            if cancelled_before_release:
                raise GitCommandError(
                    "guarded command was cancelled before release",
                    result=result,
                )
            raise GitCommandError(
                "could not release the durably registered Git guardian",
                result=result,
            ) from release_error

        deadline = time.monotonic() + self.timeout_seconds
        timed_out = False
        cancelled = False
        while status_thread.is_alive():
            if cancellation_event is not None and cancellation_event.is_set():
                cancelled = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            status_thread.join(min(0.05, remaining))

        try:
            self._terminate_guardian(
                process,
                identity,
                control_write_fd,
                child_completed=(
                    not timed_out and not cancelled and "return_code" in status
                ),
            )
        finally:
            self._close_fd(control_write_fd)
        status_thread.join(self.terminate_grace_seconds)
        stdout_capture.join(self.terminate_grace_seconds)
        stderr_capture.join(self.terminate_grace_seconds)
        clear_process(identity.process_id, identity.process_group_id)

        result = GuardedCommandResult(
            command=tuple(command),
            return_code=int(status.get("return_code", -1)),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdout_sha256=stdout_capture.digest.hexdigest(),
            stderr_sha256=stderr_capture.digest.hexdigest(),
            stdout_truncated=stdout_capture.truncated,
            stderr_truncated=stderr_capture.truncated,
        )
        if timed_out:
            raise GitCommandError(
                "Git command timed out after %.1f seconds" % self.timeout_seconds,
                result=result,
            )
        if cancelled:
            raise GitCommandError(
                "guarded command was cancelled", result=result
            )
        if "error" in status or "return_code" not in status:
            error = GitCommandError(
                "Git guardian omitted a valid child status", result=result
            )
            if "error" in status:
                raise error from status["error"]
            raise error
        if result.stdout_truncated or result.stderr_truncated:
            raise GitCommandError(
                "Git command output exceeded its bounded capture", result=result
            )
        return result

    def _inspect_stable_guardian(self, process_id: int) -> ProcessIdentity:
        deadline = time.monotonic() + min(
            2.0, self.terminate_grace_seconds * 10
        )
        previous: Optional[ProcessIdentity] = None
        stable_since: Optional[float] = None
        while time.monotonic() < deadline:
            try:
                observed = self.runtime.inspect(process_id)
            except ProcessInspectionError:
                observed = None
            now = time.monotonic()
            if (
                observed is None
                or observed.process_id != process_id
                or observed.process_group_id != process_id
            ):
                previous = None
                stable_since = None
            elif observed != previous:
                previous = observed
                stable_since = now
            elif stable_since is not None and now - stable_since >= 0.05:
                return observed
            time.sleep(0.01)
        raise ManagedWorktreeError("could not prove a stable Git guardian identity")

    def _owned_group_state(self, identity: ProcessIdentity) -> str:
        try:
            observed = self.runtime.inspect(identity.process_id)
            members = self.runtime.list_group(identity.process_group_id)
            observed_again = self.runtime.inspect(identity.process_id)
        except (OSError, ProcessInspectionError, ValueError) as error:
            raise ManagedWorktreeError(
                "could not revalidate the owned Git process group"
            ) from error
        if observed is None or observed_again is None:
            if members:
                raise ManagedWorktreeError(
                    "Git guardian is gone while its process group remains populated"
                )
            return "gone"
        if observed != identity or observed_again != identity:
            raise ManagedWorktreeError(
                "Git guardian identity changed before process-group cleanup"
            )
        member_by_pid = {member.process_id: member for member in members}
        if member_by_pid.get(identity.process_id) != identity:
            raise ManagedWorktreeError(
                "Git guardian is absent from its persisted process group"
            )
        return "guardian_only" if len(members) == 1 else "active"

    def _signal_group(self, identity: ProcessIdentity, signal_number: int) -> None:
        if self._owned_group_state(identity) == "gone":
            return
        try:
            self.runtime.signal_group(identity.process_group_id, signal_number)
        except ProcessLookupError:
            return

    def _terminate_guardian(
        self,
        process: subprocess.Popen,
        identity: ProcessIdentity,
        control_write_fd: int,
        *,
        child_completed: bool,
    ) -> None:
        state = self._owned_group_state(identity)
        if state == "gone":
            process.wait(timeout=self.terminate_grace_seconds)
            return
        if child_completed and state == "guardian_only":
            self._release_guardian(process, control_write_fd, identity)
            return

        self._signal_group(identity, signal.SIGTERM)
        deadline = time.monotonic() + self.terminate_grace_seconds
        while state == "active" and time.monotonic() < deadline:
            time.sleep(0.02)
            state = self._owned_group_state(identity)
        if child_completed and state == "guardian_only":
            self._release_guardian(process, control_write_fd, identity)
            return
        if state == "gone":
            process.wait(timeout=self.terminate_grace_seconds)
            return
        self._signal_group(identity, signal.SIGKILL)
        self._close_fd(control_write_fd)
        process.wait(timeout=self.terminate_grace_seconds)
        if not self._wait_for_group_exit(identity.process_group_id):
            raise ManagedWorktreeError(
                "Git process group did not exit after verified SIGKILL"
            )

    def _release_guardian(
        self,
        process: subprocess.Popen,
        control_write_fd: int,
        identity: ProcessIdentity,
    ) -> None:
        try:
            os.write(control_write_fd, b"1")
        except BrokenPipeError:
            pass
        finally:
            self._close_fd(control_write_fd)
        process.wait(timeout=self.terminate_grace_seconds)
        if not self._wait_for_group_exit(identity.process_group_id):
            raise ManagedWorktreeError(
                "Git process group remained populated after guardian release"
            )

    def _wait_for_group_exit(self, process_group_id: int) -> bool:
        deadline = time.monotonic() + self.terminate_grace_seconds
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group_id, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                pass
            time.sleep(0.02)
        return False

    def _wait_or_kill_unreleased(self, process: subprocess.Popen) -> None:
        try:
            process.wait(timeout=self.terminate_grace_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=self.terminate_grace_seconds)

    @staticmethod
    def _close_fd(descriptor: int) -> None:
        try:
            os.close(descriptor)
        except OSError:
            pass


class GitInspector:
    """Strict, non-mutating Git and filesystem identity inspection."""

    def __init__(self, git_executable: Path, environment: Mapping[str, str]) -> None:
        self.git_executable = git_executable
        self.environment = dict(environment)

    @classmethod
    def controlled(
        cls, environment_overrides: Optional[Mapping[str, str]] = None
    ) -> "GitInspector":
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in ("HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "TMPDIR", "USER")
        }
        environment.update(dict(environment_overrides or {}))
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_PROTOCOL_FROM_USER": "0",
                "GIT_ALLOW_PROTOCOL": "",
                "LC_ALL": "C",
            }
        )
        git = shutil.which("git", path=environment.get("PATH"))
        if git is None:
            raise ManagedWorktreeError("git was not found on the controlled PATH")
        return cls(Path(git).resolve(), environment)

    def command(self, repository: Path, *arguments: str) -> Tuple[str, ...]:
        command: List[str] = [str(self.git_executable)]
        for override in _GIT_CONFIG_OVERRIDES:
            command.extend(("-c", override))
        command.extend(("-C", str(repository)))
        command.extend(arguments)
        return tuple(command)

    def run(
        self,
        repository: Path,
        *arguments: str,
        check: bool = True,
        input_bytes: Optional[bytes] = None,
        timeout: float = 30.0,
    ) -> subprocess.CompletedProcess:
        result = subprocess.run(
            self.command(repository, *arguments),
            input=input_bytes,
            capture_output=True,
            env=self.environment,
            check=False,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            detail = result.stderr[-2000:].decode("utf-8", errors="replace").strip()
            raise ManagedWorktreeError(
                "Git inspection failed%s" % ((": " + detail) if detail else "")
            )
        return result

    def text(self, repository: Path, *arguments: str) -> str:
        return self.run(repository, *arguments).stdout.decode(
            "utf-8", errors="strict"
        ).strip()

    def path(self, repository: Path, *arguments: str) -> Path:
        value = Path(self.text(repository, *arguments))
        if not value.is_absolute():
            value = repository / value
        return value.expanduser().resolve()

    def snapshot(self, repository: Path) -> Dict[str, Any]:
        for _attempt in range(3):
            before = self._snapshot_once(repository)
            after = self._snapshot_once(repository)
            if before == after:
                return after
        else:
            raise ManagedWorktreeError(
                "source checkout changed while its baseline was captured"
            )

    def _snapshot_once(self, repository: Path) -> Dict[str, Any]:
        manifest = self._manifest(repository)
        index_path = self.path(repository, "rev-parse", "--git-path", "index")
        config_path = self.path(repository, "rev-parse", "--git-path", "config")
        index_sha256 = self._hash_optional_file(index_path)
        return {
            "head_revision": self._head_revision(repository),
            "head_ref": self._symbolic_ref(repository),
            "index_sha256": index_sha256,
            "config_sha256": self._hash_optional_file(config_path),
            "working_state_sha256": manifest["sha256"],
            "index_state_sha256": index_sha256,
            "manifest_sha256": manifest["sha256"],
            "manifest_entries": manifest["entries"],
        }

    def _manifest(self, repository: Path) -> Dict[str, Any]:
        visible = self.run(
            repository,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ).stdout.split(b"\0")
        ignored = self.run(
            repository,
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
        ).stdout.split(b"\0")
        paths = set(path for path in visible + ignored if path)
        digest = hashlib.sha256()
        entries = 0
        for raw_path in sorted(paths):
            relative = Path(os.fsdecode(raw_path))
            if relative.is_absolute() or ".." in relative.parts:
                raise ManagedWorktreeError("Git returned an unsafe checkout path")
            path = repository / relative
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                metadata = None
                kind = b"missing"
                mode = b"-"
                content_digest = b"-"
            else:
                mode = oct(stat.S_IMODE(metadata.st_mode)).encode("ascii")
            if metadata is not None and stat.S_ISREG(metadata.st_mode):
                kind = b"file"
                content_digest = self._hash_file(path).encode("ascii")
            elif metadata is not None and stat.S_ISLNK(metadata.st_mode):
                kind = b"symlink"
                content_digest = hashlib.sha256(
                    os.fsencode(os.readlink(path))
                ).hexdigest().encode("ascii")
            elif metadata is not None and stat.S_ISDIR(metadata.st_mode):
                kind = b"directory"
                content_digest = b"-"
            elif metadata is not None:
                raise ManagedWorktreeError(
                    "source checkout contains an unsupported filesystem entry"
                )
            record = b"\0".join(
                (
                    raw_path,
                    kind,
                    mode,
                    content_digest,
                )
            )
            digest.update(len(record).to_bytes(8, "big"))
            digest.update(record)
            entries += 1
        return {"sha256": digest.hexdigest(), "entries": entries}

    def reject_checkout_executables(
        self, repository: Path, revision: str
    ) -> None:
        tree = self.run(
            repository, "ls-tree", "-r", "-z", "--full-tree", revision
        ).stdout
        paths: List[bytes] = []
        for entry in (value for value in tree.split(b"\0") if value):
            metadata, separator, path = entry.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3:
                raise ManagedWorktreeError("base tree contains an invalid entry")
            if fields[0] == b"160000" or fields[1] == b"commit":
                raise ManagedWorktreeError(
                    "managed worktrees do not yet support submodule gitlinks"
                )
            paths.append(path)
        tracked = b"\0".join(paths) + (b"\0" if paths else b"")
        if not tracked:
            return
        attributes = self.run(
            repository,
            "check-attr",
            "--source=%s" % revision,
            "-z",
            "--stdin",
            "filter",
            input_bytes=tracked,
        ).stdout.split(b"\0")
        values = [attributes[index] for index in range(2, len(attributes), 3)]
        if any(value not in (b"unspecified", b"unset") for value in values):
            raise ManagedWorktreeError(
                "managed worktree checkout refuses active filter attributes"
            )

    def reject_source_checkout_executables(self, repository: Path) -> None:
        staged = self.run(repository, "ls-files", "--stage", "-z").stdout
        tracked_paths: List[bytes] = []
        for entry in (value for value in staged.split(b"\0") if value):
            metadata, separator, path = entry.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3:
                raise ManagedWorktreeError("source index contains an invalid entry")
            if fields[0] == b"160000":
                raise ManagedWorktreeError(
                    "source checkout with submodule gitlinks is unsupported"
                )
            tracked_paths.append(path)
        if not tracked_paths:
            return
        attributes = self.run(
            repository,
            "check-attr",
            "-z",
            "--stdin",
            "filter",
            input_bytes=b"\0".join(tracked_paths) + b"\0",
        ).stdout.split(b"\0")
        values = [attributes[index] for index in range(2, len(attributes), 3)]
        if any(value not in (b"unspecified", b"unset") for value in values):
            raise ManagedWorktreeError(
                "source checkout refuses active working-tree filter attributes"
            )

    def require_local_objects(self, repository: Path, revision: str) -> None:
        result = self.run(
            repository,
            "rev-list",
            "--objects",
            "--missing=print",
            revision,
        )
        if any(line.startswith(b"?") for line in result.stdout.splitlines()):
            raise ManagedWorktreeError(
                "managed worktree base contains promisor or missing objects"
            )

    def worktree_registry(self, repository: Path) -> List[Dict[str, str]]:
        fields = self.run(
            repository, "worktree", "list", "--porcelain", "-z"
        ).stdout.split(b"\0")
        records: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for entry in fields:
            if not entry:
                if current:
                    records.append(current)
                    current = {}
                continue
            key, separator, value = entry.partition(b" ")
            current[key.decode("ascii")] = (
                value.decode("utf-8", errors="surrogateescape")
                if separator
                else "true"
            )
        if current:
            records.append(current)
        return records

    def worktree_record(
        self, repository: Path, worktree_path: Path
    ) -> Optional[Dict[str, str]]:
        expected = str(worktree_path.resolve())
        for record in self.worktree_registry(repository):
            candidate = record.get("worktree")
            if candidate is not None and str(Path(candidate).resolve()) == expected:
                return record
        return None

    def inspect_ready(
        self, worktree: Mapping[str, Any]
    ) -> Dict[str, Any]:
        repository = Path(str(worktree["repository_path"]))
        path = Path(str(worktree["worktree_path"]))
        if not path.is_dir() or path.is_symlink():
            raise ManagedWorktreeError("managed worktree path is absent or replaced")
        top = self.path(path, "rev-parse", "--show-toplevel")
        common = self.path(path, "rev-parse", "--git-common-dir")
        git_dir = self.path(path, "rev-parse", "--absolute-git-dir")
        branch_ref = self.text(path, "symbolic-ref", "-q", "HEAD")
        head = self.text(path, "rev-parse", "HEAD")
        head_tree = self.text(path, "rev-parse", "HEAD^{tree}")
        object_format = self.text(path, "rev-parse", "--show-object-format")
        registry = self.worktree_record(repository, path)
        filesystem = path.stat()
        observed = {
            "worktree_id": str(worktree["id"]),
            "repository_path": str(repository.resolve()),
            "source_git_common_dir": str(common),
            "worktree_path": str(top),
            "worktree_git_dir": str(git_dir),
            "worktree_device": int(filesystem.st_dev),
            "worktree_inode": int(filesystem.st_ino),
            "worktree_owner_uid": int(filesystem.st_uid),
            "branch_ref": branch_ref,
            "base_revision": str(worktree["base_revision"]),
            "head_revision": head,
            "head_tree": head_tree,
            "object_format": object_format,
            "lock_reason": "" if registry is None else registry.get("locked", ""),
        }
        expected = {
            "repository_path": str(worktree["repository_path"]),
            "source_git_common_dir": str(worktree["source_git_common_dir"]),
            "worktree_path": str(worktree["worktree_path"]),
            "branch_ref": str(worktree["branch_ref"]),
            "base_tree": str(worktree["base_tree"]),
            "object_format": str(worktree["object_format"]),
            "lock_reason": str(worktree["lock_reason"]),
        }
        comparable = {
            **observed,
            "base_tree": observed["head_tree"],
        }
        if registry is None or any(comparable[key] != value for key, value in expected.items()):
            raise ManagedWorktreeError("managed worktree Git identity changed")
        for key in (
            "worktree_git_dir",
            "worktree_device",
            "worktree_inode",
            "worktree_owner_uid",
        ):
            persisted = worktree.get(key)
            if persisted is not None and observed[key] != persisted:
                raise ManagedWorktreeError("managed worktree %s changed" % key)
        expected_head = worktree.get("head_revision") or worktree["base_revision"]
        if head != expected_head:
            raise ManagedWorktreeError("managed worktree branch HEAD changed")
        return observed

    def inspect_source_identity(self, worktree: Mapping[str, Any]) -> Dict[str, Any]:
        repository = Path(str(worktree["repository_path"]))
        if repository.is_symlink() or not repository.is_dir():
            raise ManagedWorktreeError("source repository path is absent or replaced")
        filesystem = repository.stat()
        observed = {
            "repository_path": str(
                self.path(repository, "rev-parse", "--show-toplevel")
            ),
            "source_git_common_dir": str(
                self.path(repository, "rev-parse", "--git-common-dir")
            ),
            "source_git_dir": str(
                self.path(repository, "rev-parse", "--absolute-git-dir")
            ),
            "source_device": int(filesystem.st_dev),
            "source_inode": int(filesystem.st_ino),
            "source_owner_uid": int(filesystem.st_uid),
            "object_format": self.text(
                repository, "rev-parse", "--show-object-format"
            ),
        }
        for key, value in observed.items():
            if value != worktree.get(key):
                raise ManagedWorktreeError("source repository %s changed" % key)
        return observed

    def verify_binding(
        self,
        worktree: Mapping[str, Any],
        *,
        campaign_id: str,
        work_item_id: str,
        managed_worktree_id: str,
        source_repositories: Sequence[Path],
    ) -> Path:
        """Validate a scheduler-fenced worktree before a real worker can use it."""

        if (
            str(worktree.get("state")) != "ready"
            or str(worktree.get("id")) != managed_worktree_id
            or str(worktree.get("campaign_id")) != campaign_id
            or str(worktree.get("work_item_id")) != work_item_id
        ):
            raise ManagedWorktreeError(
                "managed worktree does not match the claimed campaign, item, and job"
            )
        repository = Path(str(worktree["repository_path"])).expanduser().resolve()
        if repository not in source_repositories:
            raise ManagedWorktreeError(
                "managed worktree repository is outside the campaign scope"
            )
        worktree_path = Path(str(worktree["worktree_path"])).expanduser().resolve()
        if worktree_path == repository:
            raise ManagedWorktreeError(
                "managed worktree must be distinct from its source checkout"
            )
        self.inspect_ready(worktree)
        self.inspect_source_identity(worktree)
        if self.snapshot(repository) != worktree.get("source_snapshot"):
            raise ManagedWorktreeError(
                "source checkout no longer matches the managed-worktree baseline"
            )
        return worktree_path

    def is_clean_for_removal(self, worktree_path: Path) -> bool:
        before = self._clean_removal_fingerprint(worktree_path)
        if before is None:
            return False
        after = self._clean_removal_fingerprint(worktree_path)
        return before == after

    def _clean_removal_fingerprint(
        self, worktree_path: Path
    ) -> Optional[Dict[str, Any]]:
        untracked = self.run(
            worktree_path,
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
        ).stdout
        ignored = self.run(
            worktree_path,
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
        ).stdout
        if untracked or ignored:
            return None
        tagged = self.run(worktree_path, "ls-files", "-v", "-z").stdout
        for record in (entry for entry in tagged.split(b"\0") if entry):
            tag = record[:1]
            if tag == b"S" or tag.islower():
                return None
        index = self._index_entries(worktree_path)
        head = self._head_tree_entries(worktree_path)
        if index != head:
            return None
        object_format = self.text(
            worktree_path, "rev-parse", "--show-object-format"
        )
        for relative, (mode, object_id) in index.items():
            path = worktree_path / Path(os.fsdecode(relative))
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                return None
            if mode == b"120000":
                if not stat.S_ISLNK(metadata.st_mode):
                    return None
                content = os.fsencode(os.readlink(path))
            elif mode in (b"100644", b"100755"):
                if not stat.S_ISREG(metadata.st_mode):
                    return None
                executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
                if executable != (mode == b"100755"):
                    return None
                content = path.read_bytes()
            else:
                return None
            actual_id = self._git_blob_oid(content, object_format)
            if actual_id != object_id.decode("ascii"):
                return None
        return {
            "untracked_sha256": hashlib.sha256(untracked).hexdigest(),
            "ignored_sha256": hashlib.sha256(ignored).hexdigest(),
            "tagged_sha256": hashlib.sha256(tagged).hexdigest(),
            "index": index,
            "head": head,
        }

    def _index_entries(self, repository: Path) -> Dict[bytes, Tuple[bytes, bytes]]:
        result: Dict[bytes, Tuple[bytes, bytes]] = {}
        for record in (
            entry
            for entry in self.run(repository, "ls-files", "--stage", "-z").stdout.split(
                b"\0"
            )
            if entry
        ):
            metadata, separator, path = record.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3 or fields[2] != b"0":
                raise ManagedWorktreeError("managed worktree index has unresolved stages")
            if path in result:
                raise ManagedWorktreeError("managed worktree index path is duplicated")
            result[path] = (fields[0], fields[1])
        return result

    def _head_tree_entries(self, repository: Path) -> Dict[bytes, Tuple[bytes, bytes]]:
        result: Dict[bytes, Tuple[bytes, bytes]] = {}
        output = self.run(
            repository, "ls-tree", "-r", "-z", "--full-tree", "HEAD"
        ).stdout
        for record in (entry for entry in output.split(b"\0") if entry):
            metadata, separator, path = record.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3 or fields[1] != b"blob":
                raise ManagedWorktreeError("managed worktree HEAD tree is unsupported")
            result[path] = (fields[0], fields[2])
        return result

    @staticmethod
    def _git_blob_oid(content: bytes, object_format: str) -> str:
        if object_format == "sha1":
            digest = hashlib.sha1()
        elif object_format == "sha256":
            digest = hashlib.sha256()
        else:
            raise ManagedWorktreeError("unsupported Git object format")
        digest.update(("blob %d\0" % len(content)).encode("ascii"))
        digest.update(content)
        return digest.hexdigest()

    def branch_head(self, repository: Path, branch_ref: str) -> Optional[str]:
        result = self.run(
            repository,
            "show-ref",
            "--verify",
            "--quiet",
            branch_ref,
            check=False,
        )
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise ManagedWorktreeError("could not inspect managed branch")
        return self.text(repository, "rev-parse", "--verify", branch_ref)

    def _symbolic_ref(self, repository: Path) -> Optional[str]:
        result = self.run(
            repository, "symbolic-ref", "-q", "HEAD", check=False
        )
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise ManagedWorktreeError("could not inspect source HEAD ref")
        return result.stdout.decode("utf-8", errors="strict").strip()

    def _head_revision(self, repository: Path) -> Optional[str]:
        result = self.run(repository, "rev-parse", "--verify", "HEAD", check=False)
        if result.returncode in (1, 128):
            return None
        if result.returncode != 0:
            raise ManagedWorktreeError("could not inspect repository HEAD")
        return result.stdout.decode("ascii").strip()

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)

    @classmethod
    def _hash_optional_file(cls, path: Path) -> Optional[str]:
        return None if not path.is_file() else cls._hash_file(path)


class ManagedWorktreeManager:
    """Provision, verify, and safely remove supervisor-owned worktrees."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        config: Optional[ManagedWorktreeConfig] = None,
        owner: Optional[str] = None,
        process_runtime: Optional[ProcessRuntime] = None,
    ) -> None:
        self.store = store
        self.config = config or ManagedWorktreeConfig()
        self.owner = owner or "agent-flow-worktree-%d-%s" % (
            os.getpid(),
            uuid.uuid4().hex,
        )
        self.inspector = GitInspector.controlled(self.config.environment_overrides)
        self.environment = dict(self.inspector.environment)
        self.git_executable = self.inspector.git_executable
        self.command_runner = GuardedGitCommandRunner(
            runtime=process_runtime or DarwinProcessRuntime(),
            timeout_seconds=self.config.command_timeout_seconds,
            terminate_grace_seconds=self.config.terminate_grace_seconds,
            max_output_bytes=self.config.max_output_bytes,
        )
        self.process_reconciler = ExternalProcessReconciler(
            runtime=process_runtime or DarwinProcessRuntime(),
            terminate_grace_seconds=self.config.terminate_grace_seconds,
        )

    def provision(
        self,
        campaign_id: str,
        work_item_id: str,
        repository_path: Path,
        base: str,
    ) -> Dict[str, Any]:
        repository = self._validate_source_repository(repository_path)
        base_revision = self.inspector.text(
            repository, "rev-parse", "--verify", "%s^{commit}" % base
        )
        base_tree = self.inspector.text(
            repository, "rev-parse", "%s^{tree}" % base_revision
        )
        object_format = self.inspector.text(
            repository, "rev-parse", "--show-object-format"
        )
        self.inspector.require_local_objects(repository, base_revision)
        self.inspector.reject_checkout_executables(repository, base_revision)
        self.inspector.reject_source_checkout_executables(repository)
        source_common = self.inspector.path(
            repository, "rev-parse", "--git-common-dir"
        )
        source_git_dir = self.inspector.path(
            repository, "rev-parse", "--absolute-git-dir"
        )
        source_stat = repository.stat()
        snapshot = self.inspector.snapshot(repository)
        worktree_id = uuid.uuid4().hex
        branch_ref = "refs/heads/agent-flow/%s/%s/%s" % (
            self._hash_part(str(source_common)),
            self._hash_part(work_item_id),
            worktree_id[:12],
        )
        branch_name = branch_ref[len("refs/heads/") :]
        branch_check = self.inspector.run(
            repository, "check-ref-format", "--branch", branch_name, check=False
        )
        if branch_check.returncode != 0:
            raise ManagedWorktreeError("generated managed branch is invalid")
        if self.inspector.branch_head(repository, branch_ref) is not None:
            raise ManagedWorktreeError("generated managed branch already exists")
        root = self._prepare_root(repository, source_common)
        worktree_path = root / self._hash_part(campaign_id) / self._hash_part(
            work_item_id
        ) / worktree_id
        self._prepare_destination(worktree_path)
        lock_reason = "agent-flow:%s" % worktree_id
        request = self.store.request_managed_worktree(
            campaign_id,
            work_item_id,
            worktree_id=worktree_id,
            repository_path=str(repository),
            source_git_common_dir=str(source_common),
            source_git_dir=str(source_git_dir),
            source_device=int(source_stat.st_dev),
            source_inode=int(source_stat.st_ino),
            source_owner_uid=int(source_stat.st_uid),
            object_format=object_format,
            worktree_path=str(worktree_path),
            branch_ref=branch_ref,
            base_revision=base_revision,
            base_tree=base_tree,
            lock_reason=lock_reason,
            source_snapshot=snapshot,
            owner=self.owner,
            lease_seconds=self.config.operation_lease_seconds,
        )
        operation = request["operation"]
        worktree = request["worktree"]
        expected = dict(operation["expected_identity"])
        try:
            command = self.inspector.command(
                repository,
                "worktree",
                "add",
                "--lock",
                "--reason",
                lock_reason,
                "--no-track",
                "--no-guess-remote",
                "-b",
                branch_name,
                "--",
                str(worktree_path),
                base_revision,
            )
            result = self._run_operation_command(operation, repository, command)
            self._record_command_artifacts(operation, result)
            if result.return_code != 0:
                detail = result.stderr_path.read_text(
                    encoding="utf-8", errors="replace"
                )[-2000:].strip()
                raise GitCommandError(
                    "git worktree add failed%s" % ((": " + detail) if detail else "")
                )
            observed = self.inspector.inspect_ready(
                {**worktree, "head_revision": base_revision}
            )
            self.inspector.inspect_source_identity(worktree)
            after = self.inspector.snapshot(repository)
            return self.store.complete_managed_worktree_creation(
                str(operation["id"]),
                self.owner,
                str(operation["fencing_token"]),
                expected,
                observed,
                after,
            )
        except BaseException as error:
            self._quarantine_if_fenced(operation, expected, error)
            raise

    def verify(self, worktree_id: str) -> Dict[str, Any]:
        worktree = self.store.get_managed_worktree(worktree_id)
        if worktree["state"] != "ready":
            raise ManagedWorktreeError("managed worktree is not ready")
        self._assert_path_in_root(Path(str(worktree["worktree_path"])))
        observed = self.inspector.inspect_ready(worktree)
        self.inspector.inspect_source_identity(worktree)
        source_snapshot = self.inspector.snapshot(
            Path(str(worktree["repository_path"]))
        )
        if source_snapshot != worktree["source_snapshot"]:
            raise ManagedWorktreeError(
                "source checkout no longer matches its persisted baseline"
            )
        return observed

    def reconcile_expired(self, *, limit: int = 25) -> Tuple[ReconciliationResult, ...]:
        """Reconcile expired lifecycle operations under a separate durable fence."""

        claimed = self.store.claim_expired_worktree_operations(
            self.owner,
            lease_seconds=self.config.operation_lease_seconds,
            limit=limit,
        )
        results: List[ReconciliationResult] = []
        for record in claimed:
            operation = record["operation"]
            worktree = record["worktree"]
            token = str(operation["reconciliation_token"])
            expected = dict(operation["expected_identity"])
            binding = self._operation_binding(operation)
            try:
                process_result: Optional[ReconciliationResult] = None
                if binding is not None and operation.get("process_state") == "active":
                    process_result = self.process_reconciler.reconcile(binding)
                    if not process_result.can_release:
                        self.store.quarantine_worktree_operation(
                            str(operation["id"]),
                            self.owner,
                            token,
                            expected,
                            process_result.reason,
                            observed_identity=process_result.observed,
                            reconciliation=True,
                            allow_active_process=True,
                        )
                        results.append(process_result)
                        continue
                    self.store.clear_worktree_operation_process(
                        str(operation["id"]),
                        self.owner,
                        token,
                        binding.process_id,
                        binding.process_group_id,
                        reconciliation=True,
                    )
                self._recover_operation_artifacts(operation, token)
                if str(operation["kind"]) == "create":
                    self._reconcile_creation(operation, worktree, token, expected)
                elif str(operation["kind"]) == "remove":
                    self._reconcile_removal(operation, worktree, token, expected)
                else:
                    raise ManagedWorktreeError("unknown worktree operation kind")
                results.append(
                    ReconciliationResult(
                        binding or self._placeholder_binding(operation),
                        (
                            process_result.status
                            if process_result is not None
                            else ReconciliationStatus.GONE
                        ),
                        "expired lifecycle operation was reconciled from exact Git state",
                    )
                )
            except BaseException as error:
                reason = "%s: %s" % (type(error).__name__, error)
                try:
                    self.store.quarantine_worktree_operation(
                        str(operation["id"]),
                        self.owner,
                        token,
                        expected,
                        reason,
                        reconciliation=True,
                    )
                except Exception as persistence_error:
                    reason += "; quarantine persistence failed: %s" % persistence_error
                results.append(
                    ReconciliationResult(
                        binding or self._placeholder_binding(operation),
                        ReconciliationStatus.QUARANTINED,
                        reason,
                    )
                )
        return tuple(results)

    def retry_quarantined_processes(
        self, *, limit: int = 25
    ) -> Tuple[ReconciliationResult, ...]:
        """Reap a quarantined guardian, then adopt only exact lifecycle state."""

        claimed = self.store.claim_quarantined_worktree_processes(
            self.owner,
            lease_seconds=self.config.operation_lease_seconds,
            limit=limit,
        )
        results: List[ReconciliationResult] = []
        for record in claimed:
            operation = record["operation"]
            worktree = record["worktree"]
            binding = self._operation_binding(operation)
            token = str(operation["reconciliation_token"])
            expected = dict(operation["expected_identity"])
            if binding is None:
                result = ReconciliationResult(
                    self._placeholder_binding(operation),
                    ReconciliationStatus.QUARANTINED,
                    "quarantined operation has no durable process identity",
                )
            elif operation.get("process_state") == "stopped":
                result = ReconciliationResult(
                    binding,
                    ReconciliationStatus.GONE,
                    "durable quarantined guardian was already reaped",
                )
            else:
                result = self.process_reconciler.reconcile(binding)
            try:
                if result.can_release and binding is not None:
                    if operation.get("process_state") == "active":
                        self.store.clear_worktree_operation_process(
                            str(operation["id"]),
                            self.owner,
                            token,
                            binding.process_id,
                            binding.process_group_id,
                            reconciliation=True,
                        )
                    resumed = self.store.resume_quarantined_worktree_operation(
                        str(operation["id"]), self.owner, token
                    )
                    self._recover_operation_artifacts(resumed, token)
                    if str(operation["kind"]) == "create":
                        self._reconcile_creation(
                            resumed, worktree, token, expected
                        )
                    elif str(operation["kind"]) == "remove":
                        self._reconcile_removal(
                            resumed, worktree, token, expected
                        )
                    else:
                        raise ManagedWorktreeError(
                            "unknown worktree operation kind"
                        )
                    result = ReconciliationResult(
                        binding,
                        result.status,
                        "quarantined guardian was reaped and exact Git state was adopted",
                        result.observed,
                    )
                else:
                    self.store.finish_quarantined_worktree_process_retry(
                        str(operation["id"]),
                        self.owner,
                        token,
                        reason=result.reason,
                        observed_identity=result.observed,
                    )
            except BaseException as error:
                reason = "%s; exact lifecycle recovery failed: %s" % (
                    result.reason,
                    error,
                )
                try:
                    refreshed = next(
                        candidate
                        for candidate in self.store.list_worktree_operations(
                            managed_worktree_id=str(operation["managed_worktree_id"])
                        )
                        if candidate["id"] == operation["id"]
                    )
                    if refreshed["status"] == "running":
                        self.store.quarantine_worktree_operation(
                            str(operation["id"]),
                            self.owner,
                            token,
                            expected,
                            reason,
                            reconciliation=True,
                        )
                    else:
                        self.store.finish_quarantined_worktree_process_retry(
                            str(operation["id"]),
                            self.owner,
                            token,
                            reason=reason,
                            observed_identity=result.observed,
                        )
                except BaseException as persistence_error:
                    reason += "; retry persistence failed: %s" % persistence_error
                result = ReconciliationResult(
                    binding or self._placeholder_binding(operation),
                    ReconciliationStatus.QUARANTINED,
                    reason,
                    result.observed,
                )
            results.append(result)
        return tuple(results)

    def cleanup(self, worktree_id: str) -> Dict[str, Any]:
        current = self.store.get_managed_worktree(worktree_id)
        self._prepare_root(
            Path(str(current["repository_path"])),
            Path(str(current["source_git_common_dir"])),
        )
        request = self.store.request_managed_worktree_cleanup(
            worktree_id,
            self.owner,
            lease_seconds=self.config.operation_lease_seconds,
        )
        operation = request["operation"]
        worktree = request["worktree"]
        expected = dict(operation["expected_identity"])
        repository = Path(str(worktree["repository_path"]))
        worktree_path = Path(str(worktree["worktree_path"]))
        try:
            self._assert_path_in_root(worktree_path)
            self.inspector.inspect_ready({**worktree, "state": "ready"})
            self.inspector.inspect_source_identity(worktree)
            if not self.inspector.is_clean_for_removal(worktree_path):
                raise ManagedWorktreeError(
                    "managed worktree is dirty or contains ignored files; cleanup refused"
                )
            before = self.inspector.snapshot(repository)
            if before != worktree["source_snapshot"]:
                raise ManagedWorktreeError(
                    "source checkout changed before managed worktree cleanup"
                )
            if not self.inspector.is_clean_for_removal(worktree_path):
                raise ManagedWorktreeError(
                    "managed worktree changed during cleanup preflight"
                )
            unlock = self.inspector.command(
                repository, "worktree", "unlock", str(worktree_path)
            )
            remove = self.inspector.command(
                repository, "worktree", "remove", str(worktree_path)
            )
            remove_sequence = (
                sys.executable,
                "-c",
                _GIT_REMOVE_SEQUENCE,
                json.dumps(unlock),
                json.dumps(remove),
            )
            remove_result = self._run_operation_command(
                operation,
                repository,
                remove_sequence,
            )
            self._record_command_artifacts(operation, remove_result)
            if remove_result.return_code != 0:
                raise GitCommandError(
                    "git worktree unlock/remove refused the managed worktree"
                )
            after = self.inspector.snapshot(repository)
            branch_head = self.inspector.branch_head(
                repository, str(worktree["branch_ref"])
            )
            observed = {
                "worktree_id": worktree_id,
                "path_absent": not os.path.lexists(str(worktree_path)),
                "registry_absent": self.inspector.worktree_record(
                    repository, worktree_path
                )
                is None,
                "branch_ref": worktree["branch_ref"],
                "branch_head_revision": branch_head,
            }
            return self.store.complete_managed_worktree_removal(
                str(operation["id"]),
                self.owner,
                str(operation["fencing_token"]),
                expected,
                observed,
                after,
            )
        except BaseException as error:
            self._quarantine_if_fenced(operation, expected, error)
            raise

    def _run_operation_command(
        self,
        operation: Mapping[str, Any],
        cwd: Path,
        command: Sequence[str],
    ) -> GuardedCommandResult:
        operation_id = str(operation["id"])
        token = str(operation["fencing_token"])
        artifact_directory = self.config.runtime_root / self._hash_part(operation_id)
        self.store.record_worktree_operation_artifact_intent(
            operation_id,
            self.owner,
            token,
            stdout_path=str(artifact_directory / "stdout.log"),
            stderr_path=str(artifact_directory / "stderr.log"),
        )

        def record(identity: ProcessIdentity, target: str) -> None:
            self.store.record_worktree_operation_process(
                operation_id,
                self.owner,
                token,
                process_id=identity.process_id,
                process_group_id=identity.process_group_id,
                process_owner_uid=identity.user_id,
                process_start_seconds=identity.start_seconds,
                process_start_microseconds=identity.start_microseconds,
                process_kernel_executable=identity.executable,
                process_target_executable=target,
            )

        def clear(process_id: int, process_group_id: int) -> None:
            self.store.clear_worktree_operation_process(
                operation_id,
                self.owner,
                token,
                process_id,
                process_group_id,
            )

        try:
            return self.command_runner.run(
                command,
                cwd=cwd,
                environment=self.environment,
                artifact_directory=artifact_directory,
                record_process=record,
                clear_process=clear,
            )
        except GitCommandError as error:
            if error.result is not None:
                self._record_command_artifacts(operation, error.result)
            raise

    def _record_command_artifacts(
        self,
        operation: Mapping[str, Any],
        result: GuardedCommandResult,
    ) -> None:
        self.store.record_worktree_operation_artifacts(
            str(operation["id"]),
            self.owner,
            str(operation["fencing_token"]),
            stdout_path=str(result.stdout_path),
            stdout_sha256=result.stdout_sha256,
            stderr_path=str(result.stderr_path),
            stderr_sha256=result.stderr_sha256,
        )

    def _quarantine_if_fenced(
        self,
        operation: Mapping[str, Any],
        expected: Mapping[str, Any],
        error: BaseException,
    ) -> None:
        try:
            refreshed = next(
                record
                for record in self.store.list_worktree_operations(
                    managed_worktree_id=str(operation["managed_worktree_id"])
                )
                if record["id"] == operation["id"]
            )
            if refreshed.get("process_state") == "active":
                return
            self.store.quarantine_worktree_operation(
                str(operation["id"]),
                self.owner,
                str(operation["fencing_token"]),
                expected,
                "%s: %s" % (type(error).__name__, error),
            )
        except Exception:
            return

    def _validate_source_repository(self, repository_path: Path) -> Path:
        expanded = repository_path.expanduser()
        if expanded.is_symlink():
            raise ManagedWorktreeError("source repository path cannot be a symlink")
        repository = expanded.resolve()
        if not repository.is_dir():
            raise ManagedWorktreeError("source repository does not exist")
        top = self.inspector.path(repository, "rev-parse", "--show-toplevel")
        if top != repository:
            raise ManagedWorktreeError("source repository must be its Git top-level")
        if self.inspector.text(repository, "rev-parse", "--is-bare-repository") != "false":
            raise ManagedWorktreeError("bare repositories cannot own managed worktrees")
        return repository

    def _reconcile_creation(
        self,
        operation: Mapping[str, Any],
        worktree: Mapping[str, Any],
        token: str,
        expected: Mapping[str, Any],
    ) -> None:
        observed = self.inspector.inspect_ready(
            {**worktree, "head_revision": worktree["base_revision"]}
        )
        self.inspector.inspect_source_identity(worktree)
        repository = Path(str(worktree["repository_path"]))
        after = self.inspector.snapshot(repository)
        self.store.complete_managed_worktree_creation(
            str(operation["id"]),
            self.owner,
            token,
            expected,
            observed,
            after,
            reconciliation=True,
        )

    def _reconcile_removal(
        self,
        operation: Mapping[str, Any],
        worktree: Mapping[str, Any],
        token: str,
        expected: Mapping[str, Any],
    ) -> None:
        repository = Path(str(worktree["repository_path"]))
        worktree_path = Path(str(worktree["worktree_path"]))
        self._assert_path_in_root(worktree_path)
        self.inspector.inspect_source_identity(worktree)
        observed = {
            "worktree_id": worktree["id"],
            "path_absent": not os.path.lexists(str(worktree_path)),
            "registry_absent": self.inspector.worktree_record(
                repository, worktree_path
            )
            is None,
            "branch_ref": worktree["branch_ref"],
            "branch_head_revision": self.inspector.branch_head(
                repository, str(worktree["branch_ref"])
            ),
        }
        after = self.inspector.snapshot(repository)
        self.store.complete_managed_worktree_removal(
            str(operation["id"]),
            self.owner,
            token,
            expected,
            observed,
            after,
            reconciliation=True,
        )

    def _recover_operation_artifacts(
        self, operation: Mapping[str, Any], token: str
    ) -> None:
        if operation.get("process_id") is None:
            raise ManagedWorktreeError(
                "lifecycle operation has no durable process identity to reconcile"
            )
        operation_id = str(operation["id"])
        expected_directory = (
            self.config.runtime_root.expanduser().resolve()
            / self._hash_part(operation_id)
        )
        stdout_path = Path(str(operation.get("stdout_path") or ""))
        stderr_path = Path(str(operation.get("stderr_path") or ""))
        expected_paths = (
            expected_directory / "stdout.log",
            expected_directory / "stderr.log",
        )
        if (stdout_path, stderr_path) != expected_paths:
            raise ManagedWorktreeError(
                "lifecycle artifact intent does not match the configured runtime root"
            )
        for path in expected_paths:
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_uid != os.getuid()
            ):
                raise ManagedWorktreeError(
                    "lifecycle artifact is absent, replaced, or not user-owned"
                )
        stdout_hash = self._sha256(stdout_path)
        stderr_hash = self._sha256(stderr_path)
        for key, value in (
            ("stdout_sha256", stdout_hash),
            ("stderr_sha256", stderr_hash),
        ):
            persisted = operation.get(key)
            if persisted is not None and persisted != value:
                raise ManagedWorktreeError("persisted lifecycle artifact hash changed")
        self.store.record_worktree_operation_artifacts(
            operation_id,
            self.owner,
            token,
            stdout_path=str(stdout_path),
            stdout_sha256=stdout_hash,
            stderr_path=str(stderr_path),
            stderr_sha256=stderr_hash,
            reconciliation=True,
        )

    @staticmethod
    def _operation_binding(
        operation: Mapping[str, Any]
    ) -> Optional[ExternalProcessBinding]:
        if operation.get("process_id") is None:
            return None
        return ExternalProcessBinding.from_mapping(
            {
                "job_id": "worktree:%s" % operation["managed_worktree_id"],
                "attempt_id": operation["id"],
                "process_id": operation["process_id"],
                "process_group_id": operation["process_group_id"],
                "owner_uid": operation["process_owner_uid"],
                "kernel_executable": operation["process_kernel_executable"],
                "start_seconds": operation["process_start_seconds"],
                "start_microseconds": operation["process_start_microseconds"],
                "target_executable": operation["process_target_executable"],
                "identity_version": operation["process_identity_version"],
            }
        )

    @staticmethod
    def _placeholder_binding(operation: Mapping[str, Any]) -> ExternalProcessBinding:
        return ExternalProcessBinding(
            job_id="worktree:%s" % operation["managed_worktree_id"],
            attempt_id=str(operation["id"]),
            process_id=0,
            process_group_id=0,
            user_id=None,
            executable=None,
            start_seconds=None,
            start_microseconds=None,
            target_executable=None,
        )

    def _prepare_root(self, repository: Path, source_common: Path) -> Path:
        configured_root = self.config.worktree_root.expanduser()
        configured_runtime = self.config.runtime_root.expanduser()
        self._assert_no_symlink_components(configured_root)
        self._assert_no_symlink_components(configured_runtime)
        root = configured_root.resolve()
        runtime = configured_runtime.resolve()
        if self._overlaps(root, repository) or self._overlaps(root, source_common):
            raise ManagedWorktreeError(
                "managed worktree root must be outside the source repository"
            )
        if self._overlaps(root, runtime):
            raise ManagedWorktreeError(
                "managed worktrees and runtime artifacts must use separate roots"
            )
        if self._overlaps(runtime, repository) or self._overlaps(
            runtime, source_common
        ):
            raise ManagedWorktreeError(
                "worktree runtime artifacts must be outside the source repository"
            )
        self._mkdir_secure(configured_root)
        self._mkdir_secure(configured_runtime)
        return root

    def _prepare_destination(self, destination: Path) -> None:
        self._assert_path_in_root(destination)
        if destination.exists() or destination.is_symlink():
            raise ManagedWorktreeError("managed worktree destination already exists")
        self._mkdir_secure(destination.parent)
        if destination.exists() or destination.is_symlink():
            raise ManagedWorktreeError("managed worktree destination changed concurrently")

    def _assert_path_in_root(self, path: Path) -> None:
        configured_root = self.config.worktree_root.expanduser()
        self._assert_no_symlink_components(configured_root)
        root = configured_root.resolve()
        try:
            path.resolve().relative_to(root)
        except ValueError as error:
            raise ManagedWorktreeError(
                "managed worktree path is outside the configured root"
            ) from error
        current = root
        relative = path.resolve().relative_to(root)
        for part in relative.parts[:-1]:
            current = current / part
            if current.exists() and current.is_symlink():
                raise ManagedWorktreeError(
                    "managed worktree path contains a symlink ancestor"
                )

    @staticmethod
    def _mkdir_secure(path: Path) -> None:
        path = path.expanduser()
        if not path.is_absolute():
            raise ManagedWorktreeError("managed worktree parent must be absolute")
        current = Path(path.anchor)
        creating = False
        for part in path.parts[1:]:
            current = current / part
            try:
                current_stat = current.lstat()
            except FileNotFoundError:
                try:
                    os.mkdir(str(current), 0o700)
                except FileExistsError:
                    pass
                current_stat = current.lstat()
                creating = True
            if stat.S_ISLNK(current_stat.st_mode):
                raise ManagedWorktreeError(
                    "managed worktree parent contains a symlink"
                )
            if not stat.S_ISDIR(current_stat.st_mode):
                raise ManagedWorktreeError(
                    "managed worktree parent is not a directory"
                )
            if creating or current == path:
                if current_stat.st_uid != os.getuid():
                    raise ManagedWorktreeError(
                        "managed worktree parent is not user-owned"
                    )
                if stat.S_IMODE(current_stat.st_mode) & 0o077:
                    raise ManagedWorktreeError(
                        "managed worktree parent permissions are not private"
                    )

    @staticmethod
    def _assert_no_symlink_components(path: Path) -> None:
        path = path.expanduser()
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                current_stat = current.lstat()
            except FileNotFoundError:
                return
            if stat.S_ISLNK(current_stat.st_mode):
                raise ManagedWorktreeError(
                    "managed worktree root contains a symlink"
                )

    @staticmethod
    def _hash_part(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)

    @staticmethod
    def _overlaps(first: Path, second: Path) -> bool:
        try:
            first.relative_to(second)
            return True
        except ValueError:
            pass
        try:
            second.relative_to(first)
            return True
        except ValueError:
            return False
