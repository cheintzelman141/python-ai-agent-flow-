"""Identity-safe restart reconciliation for supervisor-owned process groups.

The reconciler performs operating-system inspection and signaling only. SQLite
remains the authority that decides whether an observed result still matches a
persisted, expired attempt before releasing resources or requeueing work.
"""

from __future__ import annotations

import ctypes
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple


class ProcessInspectionError(RuntimeError):
    """The local OS could not prove a process identity safely."""


@dataclass(frozen=True)
class ProcessIdentity:
    """Kernel-observed identity that changes when a PID is reused."""

    process_id: int
    process_group_id: int
    user_id: int
    executable: str
    start_seconds: int
    start_microseconds: int

    def fingerprint(self) -> Tuple[int, int, int, str, int, int]:
        return (
            self.process_id,
            self.process_group_id,
            self.user_id,
            self.executable,
            self.start_seconds,
            self.start_microseconds,
        )


@dataclass(frozen=True)
class ExternalProcessBinding:
    """Exact persisted fence for one active external process launcher."""

    job_id: str
    attempt_id: str
    process_id: int
    process_group_id: int
    user_id: Optional[int]
    executable: Optional[str]
    start_seconds: Optional[int]
    start_microseconds: Optional[int]
    target_executable: Optional[str]
    identity_version: Optional[str] = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExternalProcessBinding":
        user_id = value.get("user_id", value.get("owner_uid"))
        executable = value.get("executable", value.get("kernel_executable"))
        return cls(
            job_id=str(value["job_id"]),
            attempt_id=str(value["attempt_id"]),
            process_id=int(value["process_id"]),
            process_group_id=int(value["process_group_id"]),
            user_id=None if user_id is None else int(user_id),
            executable=(None if executable is None else str(executable)),
            start_seconds=(
                None if value.get("start_seconds") is None else int(value["start_seconds"])
            ),
            start_microseconds=(
                None
                if value.get("start_microseconds") is None
                else int(value["start_microseconds"])
            ),
            target_executable=(
                None if value.get("target_executable") is None else str(value["target_executable"])
            ),
            identity_version=(
                None if value.get("identity_version") is None else str(value["identity_version"])
            ),
        )

    def persistence_identity(self) -> Dict[str, Any]:
        return {
            "process_id": self.process_id,
            "process_group_id": self.process_group_id,
            "user_id": self.user_id,
            "executable": self.executable,
            "start_seconds": self.start_seconds,
            "start_microseconds": self.start_microseconds,
            "target_executable": self.target_executable,
            "identity_version": self.identity_version,
        }

    def expected_identity(self) -> Optional[ProcessIdentity]:
        if (
            self.user_id is None
            or not self.executable
            or self.start_seconds is None
            or self.start_microseconds is None
        ):
            return None
        return ProcessIdentity(
            process_id=self.process_id,
            process_group_id=self.process_group_id,
            user_id=self.user_id,
            executable=self.executable,
            start_seconds=self.start_seconds,
            start_microseconds=self.start_microseconds,
        )


class ReconciliationStatus(str, Enum):
    GONE = "gone"
    TERMINATED = "terminated"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class ReconciliationResult:
    binding: ExternalProcessBinding
    status: ReconciliationStatus
    reason: str
    observed: Mapping[str, Any] = field(default_factory=dict)

    @property
    def can_release(self) -> bool:
        return self.status in (
            ReconciliationStatus.GONE,
            ReconciliationStatus.TERMINATED,
        )


class ProcessRuntime(Protocol):
    """OS boundary used by reconciliation and injected fakes."""

    def inspect(self, process_id: int) -> Optional[ProcessIdentity]:
        """Return the current kernel identity, or None when the PID is gone."""

    def list_group(self, process_group_id: int) -> Tuple[ProcessIdentity, ...]:
        """Return a stable snapshot of currently inspectable group members."""

    def signal_group(self, process_group_id: int, signal_number: int) -> None:
        """Signal one process group."""


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


class DarwinProcessRuntime:
    """Read exact macOS process birth and executable identity through libproc."""

    _PROC_PIDTBSDINFO = 3
    _PATH_BUFFER_SIZE = 4096

    def __init__(self) -> None:
        try:
            library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        except OSError as error:
            raise ProcessInspectionError("macOS libproc is unavailable") from error
        library.proc_pidinfo.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        library.proc_pidinfo.restype = ctypes.c_int
        library.proc_pidpath.argtypes = (
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        library.proc_pidpath.restype = ctypes.c_int
        library.proc_listpgrppids.argtypes = (
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        library.proc_listpgrppids.restype = ctypes.c_int
        self._library = library

    @staticmethod
    def _pid_is_absent(process_id: int) -> bool:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    @staticmethod
    def _group_is_absent(process_group_id: int) -> bool:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    def _read_bsd_info(self, process_id: int) -> Optional[_ProcBsdInfo]:
        info = _ProcBsdInfo()
        ctypes.set_errno(0)
        returned = self._library.proc_pidinfo(
            process_id,
            self._PROC_PIDTBSDINFO,
            0,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if returned != ctypes.sizeof(info):
            error_number = ctypes.get_errno()
            if returned == 0 and self._pid_is_absent(process_id):
                return None
            raise ProcessInspectionError(
                "cannot inspect process %d: errno %d" % (process_id, error_number)
            )
        return info

    @staticmethod
    def _bsd_fingerprint(info: _ProcBsdInfo) -> Tuple[int, int, int, int, int]:
        return (
            int(info.pbi_pid),
            int(info.pbi_pgid),
            int(info.pbi_uid),
            int(info.pbi_start_tvsec),
            int(info.pbi_start_tvusec),
        )

    def inspect(self, process_id: int) -> Optional[ProcessIdentity]:
        if process_id < 1:
            raise ValueError("process_id must be positive")
        before = self._read_bsd_info(process_id)
        if before is None:
            return None

        path_buffer = ctypes.create_string_buffer(self._PATH_BUFFER_SIZE)
        ctypes.set_errno(0)
        path_length = self._library.proc_pidpath(process_id, path_buffer, len(path_buffer))
        if path_length <= 0:
            error_number = ctypes.get_errno()
            if self._pid_is_absent(process_id):
                return None
            raise ProcessInspectionError(
                "cannot read executable for process %d: errno %d" % (process_id, error_number)
            )
        after = self._read_bsd_info(process_id)
        if after is None:
            return None
        if self._bsd_fingerprint(before) != self._bsd_fingerprint(after):
            raise ProcessInspectionError(
                "process %d identity changed while its executable was inspected" % process_id
            )
        executable = str(Path(path_buffer.value.decode("utf-8", errors="strict")).resolve())
        return ProcessIdentity(
            process_id=int(after.pbi_pid),
            process_group_id=int(after.pbi_pgid),
            user_id=int(after.pbi_uid),
            executable=executable,
            start_seconds=int(after.pbi_start_tvsec),
            start_microseconds=int(after.pbi_start_tvusec),
        )

    def list_group(self, process_group_id: int) -> Tuple[ProcessIdentity, ...]:
        if process_group_id < 1:
            raise ValueError("process_group_id must be positive")
        capacity = 64
        while capacity <= 65536:
            pids = (ctypes.c_int * capacity)()
            ctypes.set_errno(0)
            returned = self._library.proc_listpgrppids(process_group_id, pids, ctypes.sizeof(pids))
            if returned <= 0:
                error_number = ctypes.get_errno()
                if self._group_is_absent(process_group_id):
                    return ()
                raise ProcessInspectionError(
                    "cannot list process group %d: errno %d" % (process_group_id, error_number)
                )
            # proc_listpgrppids returns the number of PIDs written, while its
            # buffer-size argument is expressed in bytes.
            count = returned
            if count < capacity:
                identities = []
                process_ids = sorted(set(int(pid) for pid in pids[:count] if pid > 0))
                for process_id in process_ids:
                    identity = self.inspect(process_id)
                    if identity is not None and identity.process_group_id == process_group_id:
                        identities.append(identity)
                return tuple(identities)
            capacity *= 2
        raise ProcessInspectionError(
            "process group %d exceeded the inspection limit" % process_group_id
        )

    def signal_group(self, process_group_id: int, signal_number: int) -> None:
        os.killpg(process_group_id, signal_number)


class UnsupportedProcessRuntime:
    """Fail-closed runtime for platforms without an identity implementation."""

    def inspect(self, process_id: int) -> Optional[ProcessIdentity]:
        raise ProcessInspectionError(
            "external process reconciliation is unsupported on %s" % sys.platform
        )

    def list_group(self, process_group_id: int) -> Tuple[ProcessIdentity, ...]:
        raise ProcessInspectionError(
            "external process reconciliation is unsupported on %s" % sys.platform
        )

    def signal_group(self, process_group_id: int, signal_number: int) -> None:
        raise ProcessInspectionError(
            "external process reconciliation is unsupported on %s" % sys.platform
        )


def local_process_runtime() -> ProcessRuntime:
    if sys.platform == "darwin":
        return DarwinProcessRuntime()
    return UnsupportedProcessRuntime()


class ExternalProcessReconciler:
    """Safely terminate or quarantine one persisted launcher binding."""

    def __init__(
        self,
        runtime: Optional[ProcessRuntime] = None,
        *,
        terminate_grace_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if terminate_grace_seconds <= 0 or poll_interval_seconds <= 0:
            raise ValueError("reconciliation timing must be positive")
        self.runtime = runtime or local_process_runtime()
        self.terminate_grace_seconds = terminate_grace_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self._sleep = sleeper
        self._monotonic = monotonic

    def reconcile(self, binding: ExternalProcessBinding) -> ReconciliationResult:
        if (
            binding.process_id <= 1
            or binding.process_group_id <= 1
            or binding.process_id == os.getpid()
            or binding.process_group_id == os.getpgrp()
        ):
            return self._quarantine(
                binding,
                "persisted process identity targets a protected supervisor process",
            )
        expected = binding.expected_identity()
        if (
            binding.identity_version != "darwin_libproc_v1"
            or expected is None
            or not binding.target_executable
        ):
            return self._quarantine(
                binding,
                "persisted process identity is incomplete; migrated binding is unverifiable",
            )
        if expected.user_id != os.getuid():
            return self._quarantine(
                binding,
                "persisted process owner does not match the supervisor user",
                {"expected_user_id": expected.user_id, "supervisor_user_id": os.getuid()},
            )

        try:
            observed = self.runtime.inspect(binding.process_id)
            if observed is None:
                members = self.runtime.list_group(binding.process_group_id)
                if members:
                    return self._quarantine(
                        binding,
                        "launcher is gone but its persisted process group is still populated",
                        self._member_summary(members),
                    )
                return ReconciliationResult(
                    binding,
                    ReconciliationStatus.GONE,
                    "persisted launcher and process group are gone",
                )

            if observed.fingerprint() != expected.fingerprint():
                members = self.runtime.list_group(binding.process_group_id)
                if not members:
                    return ReconciliationResult(
                        binding,
                        ReconciliationStatus.GONE,
                        "persisted process group is gone; PID now belongs to another process",
                        {"observed": self._identity_summary(observed)},
                    )
                return self._quarantine(
                    binding,
                    "PID, PGID, owner, executable, or start identity no longer matches",
                    {
                        "expected": self._identity_summary(expected),
                        "observed": self._identity_summary(observed),
                    },
                )

            original_members = self.runtime.list_group(binding.process_group_id)
            original_by_pid = {identity.process_id: identity for identity in original_members}
            if original_by_pid.get(binding.process_id) != expected:
                return self._quarantine(
                    binding,
                    "verified launcher is not present in its persisted process group",
                    self._member_summary(original_members),
                )

            before_term = self.runtime.inspect(binding.process_id)
            if before_term != expected:
                return self._quarantine(
                    binding,
                    "launcher identity changed immediately before SIGTERM",
                    (
                        {}
                        if before_term is None
                        else {"observed": self._identity_summary(before_term)}
                    ),
                )

            try:
                self.runtime.signal_group(binding.process_group_id, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if self._wait_for_group_exit(binding.process_group_id):
                return ReconciliationResult(
                    binding,
                    ReconciliationStatus.TERMINATED,
                    "verified process group exited after SIGTERM",
                )

            remaining = self.runtime.list_group(binding.process_group_id)
            if not self._is_verified_subset(remaining, original_by_pid):
                return self._quarantine(
                    binding,
                    "process group membership changed before SIGKILL",
                    self._member_summary(remaining),
                )
            before_kill = self.runtime.inspect(binding.process_id)
            if before_kill != expected:
                return self._quarantine(
                    binding,
                    "launcher identity changed or vanished before SIGKILL",
                    (
                        {}
                        if before_kill is None
                        else {"observed": self._identity_summary(before_kill)}
                    ),
                )
            try:
                self.runtime.signal_group(binding.process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if self._wait_for_group_exit(binding.process_group_id):
                return ReconciliationResult(
                    binding,
                    ReconciliationStatus.TERMINATED,
                    "verified process group exited after SIGKILL",
                )
            return self._quarantine(
                binding,
                "verified process group remained after SIGKILL",
                self._member_summary(self.runtime.list_group(binding.process_group_id)),
            )
        except (OSError, ProcessInspectionError, ValueError) as error:
            return self._quarantine(
                binding,
                "process inspection or signaling failed: %s" % error,
            )

    def _wait_for_group_exit(self, process_group_id: int) -> bool:
        deadline = self._monotonic() + self.terminate_grace_seconds
        while True:
            try:
                members = self.runtime.list_group(process_group_id)
            except (OSError, ProcessInspectionError):
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise
                self._sleep(min(self.poll_interval_seconds, remaining))
                continue
            if not members:
                return True
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return False
            self._sleep(min(self.poll_interval_seconds, remaining))

    @staticmethod
    def _is_verified_subset(
        remaining: Tuple[ProcessIdentity, ...],
        original_by_pid: Mapping[int, ProcessIdentity],
    ) -> bool:
        return bool(remaining) and all(
            original_by_pid.get(identity.process_id) == identity for identity in remaining
        )

    @staticmethod
    def _identity_summary(identity: ProcessIdentity) -> Dict[str, Any]:
        return {
            "process_id": identity.process_id,
            "process_group_id": identity.process_group_id,
            "user_id": identity.user_id,
            "executable": identity.executable,
            "start_seconds": identity.start_seconds,
            "start_microseconds": identity.start_microseconds,
        }

    @classmethod
    def _member_summary(cls, members: Tuple[ProcessIdentity, ...]) -> Dict[str, Any]:
        return {"members": [cls._identity_summary(identity) for identity in members]}

    @staticmethod
    def _quarantine(
        binding: ExternalProcessBinding,
        reason: str,
        observed: Optional[Mapping[str, Any]] = None,
    ) -> ReconciliationResult:
        return ReconciliationResult(
            binding,
            ReconciliationStatus.QUARANTINED,
            reason,
            dict(observed or {}),
        )
