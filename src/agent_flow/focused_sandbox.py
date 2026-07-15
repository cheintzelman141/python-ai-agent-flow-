"""Deterministic macOS Seatbelt policy for authoritative focused tests.

The focused test is arbitrary repository code.  It may read the exact managed
worktree and use private HOME/TMPDIR scratch space, but it cannot read other
same-user files, write the worktree, use the network, fork, or exec another
program.  The complete profile is persisted with the execution before launch.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import List, Optional, Sequence, Tuple


DARWIN_SANDBOX_POLICY_VERSION = "darwin-seatbelt-v1"
DARWIN_SANDBOX_EXECUTABLE = Path("/usr/bin/sandbox-exec")
_MAX_PROFILE_BYTES = 32 * 1024
_MAX_RUNTIME_ENTRIES = 25_000
_MAX_RUNTIME_BYTES = 512 * 1024 * 1024
_SYSTEM_READ_SUBPATHS = (Path("/System"), Path("/usr/lib"))
_DEVICE_READ_LITERALS = (
    Path("/dev/null"),
    Path("/dev/random"),
    Path("/dev/urandom"),
)


class FocusedSandboxError(ValueError):
    """A focused test cannot be represented by the trusted sandbox policy."""


def direct_python_executable(executable: Path) -> Path:
    """Return a direct interpreter binary instead of Apple's spawning launcher."""

    resolved = _canonical_existing_path(executable, "focused Python executable")
    version_root = _framework_version_root(resolved)
    if version_root is None:
        return resolved
    direct = (
        version_root
        / "Resources"
        / "Python.app"
        / "Contents"
        / "MacOS"
        / "Python"
    )
    if direct.is_file():
        return direct.resolve(strict=True)
    return resolved


def python_runtime_root(executable: Path) -> Path:
    """Return the smallest immutable interpreter tree needed for stdlib imports."""

    resolved = _canonical_existing_path(executable, "focused Python executable")
    version_root = _framework_version_root(resolved)
    if version_root is not None:
        _validate_trusted_runtime_tree(version_root)
        return version_root
    # Non-framework installations keep their interpreter and standard library
    # under a common prefix.  Refuse /usr/bin-style launchers because allowing
    # all of /usr would unnecessarily widen the readable surface.
    parent = resolved.parent
    if parent.name == "bin" and parent.parent != Path("/usr"):
        _validate_trusted_runtime_tree(parent.parent)
        return parent.parent
    raise FocusedSandboxError(
        "focused Python executable has no narrow trusted runtime root"
    )


def python_runtime_sha256(runtime_root: Path) -> str:
    """Hash the exact trusted runtime tree without following its symlinks."""

    root = _canonical_existing_directory(
        runtime_root, "focused Python runtime root"
    )
    _validate_trusted_runtime_tree(root)
    digest = hashlib.sha256()

    def add_field(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, byteorder="big"))
        digest.update(value)

    root_details = root.lstat()
    add_field(b".")
    add_field(str(stat.S_IMODE(root_details.st_mode)).encode("ascii"))
    entry_count = 0
    runtime_bytes = 0
    for directory, directory_names, file_names in os.walk(
        str(root), topdown=True, followlinks=False
    ):
        directory_names.sort()
        file_names.sort()
        current = Path(directory)
        for name in (*directory_names, *file_names):
            path = current / name
            details = path.lstat()
            entry_count += 1
            if entry_count > _MAX_RUNTIME_ENTRIES:
                raise FocusedSandboxError(
                    "focused Python runtime exceeds its entry bound"
                )
            add_field(path.relative_to(root).as_posix().encode("utf-8"))
            add_field(str(stat.S_IMODE(details.st_mode)).encode("ascii"))
            if stat.S_ISLNK(details.st_mode):
                add_field(b"symlink")
                add_field(os.readlink(str(path)).encode("utf-8"))
            elif stat.S_ISDIR(details.st_mode):
                add_field(b"directory")
            else:
                add_field(b"file")
                runtime_bytes += details.st_size
                if runtime_bytes > _MAX_RUNTIME_BYTES:
                    raise FocusedSandboxError(
                        "focused Python runtime exceeds its byte bound"
                    )
                add_field(str(details.st_size).encode("ascii"))
                with path.open("rb") as runtime_file:
                    while True:
                        chunk = runtime_file.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                after = path.lstat()
                if (
                    details.st_dev != after.st_dev
                    or details.st_ino != after.st_ino
                    or details.st_mode != after.st_mode
                    or details.st_size != after.st_size
                    or details.st_mtime_ns != after.st_mtime_ns
                ):
                    raise FocusedSandboxError(
                        "focused Python runtime changed while being hashed"
                    )
    return digest.hexdigest()


def sandbox_executable() -> Path:
    if sys.platform != "darwin":
        raise FocusedSandboxError(
            "trusted focused tests currently require the macOS Seatbelt runtime"
        )
    resolved = _canonical_existing_path(
        DARWIN_SANDBOX_EXECUTABLE, "Seatbelt executable"
    )
    details = resolved.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_mode & 0o022
        or not os.access(str(resolved), os.X_OK)
    ):
        raise FocusedSandboxError(
            "Seatbelt executable must be root-owned, executable, and immutable"
        )
    return resolved


def build_profile(
    *,
    test_executable: Path,
    runtime_read_root: Path,
    workspace: Path,
    run_parent: Path,
) -> str:
    """Build one byte-stable deny-by-default Seatbelt profile."""

    executable = _canonical_existing_path(
        test_executable, "focused Python executable"
    )
    runtime_root = _canonical_existing_directory(
        runtime_read_root, "focused Python runtime root"
    )
    worktree = _canonical_existing_directory(workspace, "focused workspace")
    run_root = _canonical_existing_directory(run_parent, "focused run parent")
    expected_runtime_root = python_runtime_root(executable)
    if runtime_root != expected_runtime_root:
        raise FocusedSandboxError("focused Python runtime root changed")
    if _paths_overlap(runtime_root, worktree) or _paths_overlap(runtime_root, run_root):
        raise FocusedSandboxError(
            "focused Python runtime root must not overlap workspace or scratch data"
        )

    scratch_roots = (
        run_root / "environment" / "home",
        run_root / "environment" / "tmp",
    )
    read_subpaths = tuple(
        sorted(
            {
                *(str(path) for path in _SYSTEM_READ_SUBPATHS),
                str(runtime_root),
                str(worktree),
                str(run_root),
            }
        )
    )
    parent_literals = set(str(path) for path in _DEVICE_READ_LITERALS)
    for path in (
        executable,
        runtime_root,
        worktree,
        run_root,
        *_SYSTEM_READ_SUBPATHS,
        *_DEVICE_READ_LITERALS,
        *scratch_roots,
    ):
        parent_literals.add(str(path))
        parent_literals.update(str(parent) for parent in path.parents)
    private_ancestor_literals = {
        str(parent)
        for path in (worktree, run_root)
        for parent in path.parents
        if parent != Path("/")
    }

    lines: List[str] = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec",
        "  (literal %s))" % _quote(str(executable)),
    ]
    if private_ancestor_literals:
        # Traversal needs metadata access to each parent.  A literal file-read*
        # allowance also permits listing that directory, so explicitly deny
        # directory-data reads on private ancestors while leaving the exact
        # workspace and scratch roots readable below them.
        lines.append("(deny file-read-data")
        lines.extend(
            "  (literal %s)" % _quote(path)
            for path in sorted(private_ancestor_literals)
        )
        lines[-1] += ")"
    lines.append("(allow file-read*")
    lines.extend(
        "  (literal %s)" % _quote(path) for path in sorted(parent_literals)
    )
    lines.extend(
        "  (subpath %s)" % _quote(path) for path in read_subpaths
    )
    lines[-1] += ")"
    lines.append("(allow file-write*")
    lines.append("  (literal %s)" % _quote("/dev/null"))
    for path in sorted(str(path) for path in scratch_roots):
        lines.append("  (literal %s)" % _quote(path))
        lines.append("  (subpath %s)" % _quote(path))
    lines[-1] += ")"
    profile = "\n".join(lines) + "\n"
    if len(profile.encode("utf-8")) > _MAX_PROFILE_BYTES:
        raise FocusedSandboxError("focused Seatbelt profile exceeds its byte bound")
    return profile


def build_command(
    sandbox: Path, profile: str, test_command: Sequence[str]
) -> Tuple[str, ...]:
    sandbox_path = _canonical_existing_path(sandbox, "Seatbelt executable")
    if not test_command or any(
        not isinstance(argument, str) or not argument or "\x00" in argument
        for argument in test_command
    ):
        raise FocusedSandboxError("focused test command is invalid")
    if Path(test_command[0]) != Path(test_command[0]).resolve(strict=True):
        raise FocusedSandboxError(
            "focused test command requires a direct canonical executable"
        )
    return (str(sandbox_path), "-p", profile, *tuple(test_command))


def profile_sha256(profile: str) -> str:
    return hashlib.sha256(profile.encode("utf-8")).hexdigest()


def _framework_version_root(path: Path) -> Optional[Path]:
    for candidate in (path, *path.parents):
        if candidate.parent.name == "Versions" and candidate.name:
            return candidate
    return None


def _canonical_existing_path(path: Path, label: str) -> Path:
    supplied = Path(path).expanduser()
    if not supplied.is_absolute():
        raise FocusedSandboxError("%s must be absolute" % label)
    try:
        resolved = supplied.resolve(strict=True)
    except FileNotFoundError as error:
        raise FocusedSandboxError("%s is absent" % label) from error
    _validate_path_text(resolved, label)
    return resolved


def _canonical_existing_directory(path: Path, label: str) -> Path:
    resolved = _canonical_existing_path(path, label)
    details = resolved.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise FocusedSandboxError("%s must be a real directory" % label)
    return resolved


def _validate_path_text(path: Path, label: str) -> None:
    text = str(path)
    if (
        len(text.encode("utf-8")) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise FocusedSandboxError("%s contains unsafe path text" % label)


def _validate_trusted_runtime_tree(root: Path) -> None:
    root = _canonical_existing_directory(root, "focused Python runtime root")
    root_details = root.lstat()
    if root_details.st_uid != 0 or root_details.st_mode & 0o022:
        raise FocusedSandboxError(
            "focused Python runtime root must be root-owned and immutable"
        )
    entry_count = 0
    for directory, directory_names, file_names in os.walk(
        str(root), topdown=True, followlinks=False
    ):
        current = Path(directory)
        entry_count += len(directory_names) + len(file_names)
        if entry_count > _MAX_RUNTIME_ENTRIES:
            raise FocusedSandboxError(
                "focused Python runtime exceeds its entry bound"
            )
        for name in (*directory_names, *file_names):
            path = current / name
            details = path.lstat()
            if details.st_uid != 0 or details.st_mode & 0o022:
                raise FocusedSandboxError(
                    "focused Python runtime tree must be root-owned and immutable"
                )
            if stat.S_ISLNK(details.st_mode):
                try:
                    path.resolve(strict=True).relative_to(root)
                except (FileNotFoundError, ValueError) as error:
                    raise FocusedSandboxError(
                        "focused Python runtime symlinks must remain inside the runtime"
                    ) from error
            elif not (
                stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)
            ):
                raise FocusedSandboxError(
                    "focused Python runtime contains an unsupported file type"
                )


def _quote(value: str) -> str:
    if "\x00" in value:
        raise FocusedSandboxError("Seatbelt string contains a NUL byte")
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def _paths_overlap(first: Path, second: Path) -> bool:
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
