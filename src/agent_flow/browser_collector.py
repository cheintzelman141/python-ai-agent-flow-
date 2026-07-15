"""Fixed-action visible Chrome evidence collector for disposable file fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import time
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit
from urllib.request import urlopen


DEFAULT_CHROME_EXECUTABLE = Path(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)


class BrowserCollectorError(RuntimeError):
    """A sanitized fixed browser collection failure."""


class _CDPConnection:
    def __init__(self, websocket_url: str, deadline: float) -> None:
        parsed = urlsplit(websocket_url)
        if (
            parsed.scheme != "ws"
            or parsed.hostname not in ("127.0.0.1", "localhost")
            or parsed.port is None
            or not parsed.path.startswith("/devtools/page/")
        ):
            raise BrowserCollectorError("Chrome returned an invalid page endpoint")
        timeout = max(0.1, deadline - time.monotonic())
        self.socket = socket.create_connection(
            (parsed.hostname, parsed.port), timeout=timeout
        )
        self.socket.settimeout(timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
            % (parsed.path, parsed.hostname, parsed.port, key)
        )
        self.socket.sendall(request.encode("ascii"))
        response = self._read_until(b"\r\n\r\n", 16 * 1024)
        if not response.startswith(b"HTTP/1.1 101"):
            self.close()
            raise BrowserCollectorError("Chrome rejected the page connection")
        self.deadline = deadline
        self.next_id = 1

    def _read_until(self, marker: bytes, limit: int) -> bytes:
        payload = bytearray()
        while marker not in payload:
            chunk = self.socket.recv(4096)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > limit:
                raise BrowserCollectorError("Chrome endpoint response exceeded its bound")
        return bytes(payload)

    def _read_exact(self, size: int) -> bytes:
        payload = bytearray()
        while len(payload) < size:
            chunk = self.socket.recv(size - len(payload))
            if not chunk:
                raise BrowserCollectorError("Chrome page connection closed unexpectedly")
            payload.extend(chunk)
        return bytes(payload)

    def _send_frame(self, payload: bytes, opcode: int = 1) -> None:
        mask = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def _receive_text(self) -> str:
        fragments = bytearray()
        while True:
            first, second = self._read_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > 16 * 1024 * 1024:
                raise BrowserCollectorError("Chrome page message exceeded its bound")
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(length)
            if masked:
                payload = bytes(
                    value ^ mask[index % 4]
                    for index, value in enumerate(payload)
                )
            if opcode == 8:
                raise BrowserCollectorError("Chrome page connection closed")
            if opcode == 9:
                self._send_frame(payload, opcode=10)
                continue
            if opcode not in (0, 1):
                continue
            fragments.extend(payload)
            if final:
                try:
                    return fragments.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise BrowserCollectorError(
                        "Chrome page returned invalid text"
                    ) from error

    def command(
        self, method: str, parameters: Optional[Mapping[str, Any]] = None
    ) -> Mapping[str, Any]:
        identifier = self.next_id
        self.next_id += 1
        payload = json.dumps(
            {"id": identifier, "method": method, "params": dict(parameters or {})},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.socket.settimeout(max(0.1, self.deadline - time.monotonic()))
        self._send_frame(payload)
        while time.monotonic() < self.deadline:
            try:
                response = json.loads(self._receive_text())
            except json.JSONDecodeError as error:
                raise BrowserCollectorError("Chrome page returned invalid JSON") from error
            if not isinstance(response, dict) or response.get("id") != identifier:
                continue
            if "error" in response or not isinstance(response.get("result"), dict):
                raise BrowserCollectorError("Chrome rejected a fixed collector command")
            return response["result"]
        raise BrowserCollectorError("Chrome collector timed out")

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass


class BrowserEvidenceCollector:
    """Navigate, assert, and capture one exact disposable file route."""

    _STATE_EXPRESSION = (
        "JSON.stringify({route:location.href,title:document.title,"
        "body:document.body?document.body.innerText.trim():''})"
    )

    def __init__(
        self,
        chrome_executable: Path = DEFAULT_CHROME_EXECUTABLE,
        *,
        start_new_session: bool = True,
    ) -> None:
        self.chrome_executable = chrome_executable.resolve()
        self.start_new_session = start_new_session

    def collect(self, contract: Mapping[str, Any]) -> Dict[str, str]:
        process: Optional[subprocess.Popen] = None
        connection: Optional[_CDPConnection] = None
        try:
            prepared = self._validate_contract(contract)
            process = self._launch(prepared)
            deadline = time.monotonic() + prepared["timeout_seconds"]
            websocket_url = self._page_endpoint(
                prepared["user_data_dir"], deadline, process
            )
            connection = _CDPConnection(websocket_url, deadline)
            connection.command("Page.enable")
            connection.command("Runtime.enable")
            connection.command("Page.navigate", {"url": prepared["route"]})
            state = self._page_state(connection, deadline)
            screenshot_result = connection.command(
                "Page.captureScreenshot",
                {"format": "png", "fromSurface": True},
            )
            encoded = screenshot_result.get("data")
            if not isinstance(encoded, str):
                raise BrowserCollectorError("Chrome omitted the screenshot")
            try:
                screenshot = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                raise BrowserCollectorError("Chrome returned an invalid screenshot") from error
            if (
                not screenshot.startswith(b"\x89PNG\r\n\x1a\n")
                or len(screenshot) > 16 * 1024 * 1024
            ):
                raise BrowserCollectorError("Chrome returned an invalid screenshot")
            screenshot_path = prepared["screenshot_path"]
            with screenshot_path.open("xb") as artifact:
                os.chmod(screenshot_path, 0o600)
                artifact.write(screenshot)
                artifact.flush()
                os.fsync(artifact.fileno())
            return {
                "execution_id": prepared["execution_id"],
                "observed_route": state["route"],
                "observed_title": state["title"],
                "observed_body_text": state["body"],
                "screenshot_path": str(screenshot_path),
                "screenshot_sha256": hashlib.sha256(screenshot).hexdigest(),
            }
        except BrowserCollectorError:
            raise
        except BaseException as error:
            raise BrowserCollectorError("fixed visible Chrome collection failed") from error
        finally:
            if connection is not None:
                try:
                    connection.command("Browser.close")
                except (BrowserCollectorError, OSError):
                    pass
                connection.close()
            if process is not None:
                self._terminate_process(process)

    def _validate_contract(self, contract: Mapping[str, Any]) -> Dict[str, Any]:
        execution_id = contract.get("id")
        route = contract.get("route")
        screenshot_path_value = contract.get("screenshot_path")
        configuration = contract.get("chrome_configuration")
        timeout = contract.get("timeout_seconds")
        if (
            not isinstance(execution_id, str)
            or len(execution_id) != 32
            or not isinstance(route, str)
            or urlsplit(route).scheme != "file"
            or not isinstance(screenshot_path_value, str)
            or not isinstance(configuration, Mapping)
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < float(timeout) <= 120
        ):
            raise BrowserCollectorError("prepared browser contract is incomplete")
        route_path = Path(urlsplit(route).path).resolve()
        screenshot_path = Path(screenshot_path_value)
        user_data_value = configuration.get("user_data_dir")
        profile_directory = configuration.get("profile_directory")
        if (
            not str(route_path).startswith("/private/tmp/agent-flow-")
            or not route_path.is_file()
            or not isinstance(user_data_value, str)
            or not isinstance(profile_directory, str)
            or profile_directory != profile_directory.strip()
            or profile_directory in (".", "..")
            or "/" in profile_directory
            or "\\" in profile_directory
        ):
            raise BrowserCollectorError("prepared browser fixture is invalid")
        user_data_dir = Path(user_data_value)
        if (
            not user_data_dir.is_absolute()
            or str(user_data_dir) != str(user_data_dir.resolve())
            or not str(user_data_dir).startswith("/private/tmp/agent-flow-")
            or screenshot_path.name != "screenshot.png"
            or not screenshot_path.is_absolute()
            or str(screenshot_path) != str(screenshot_path.resolve())
            or not str(screenshot_path).startswith("/private/tmp/agent-flow-")
            or screenshot_path.exists()
            or screenshot_path.is_symlink()
        ):
            raise BrowserCollectorError("prepared browser paths are invalid")
        if user_data_dir.exists():
            details = user_data_dir.lstat()
            if (
                not user_data_dir.is_dir()
                or details.st_uid != os.getuid()
                or details.st_mode & 0o077
            ):
                raise BrowserCollectorError("disposable Chrome profile is not private")
        else:
            user_data_dir.mkdir(mode=0o700, parents=True)
            os.chmod(user_data_dir, 0o700)
        for marker_name in (
            "DevToolsActivePort",
            "SingletonCookie",
            "SingletonLock",
            "SingletonSocket",
        ):
            marker = user_data_dir / marker_name
            if marker.exists() or marker.is_symlink():
                raise BrowserCollectorError(
                    "disposable Chrome profile has existing session state"
                )
        parent = screenshot_path.parent.lstat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise BrowserCollectorError("browser artifact directory is not private")
        if not self.chrome_executable.is_file() or not os.access(
            self.chrome_executable, os.X_OK
        ):
            raise BrowserCollectorError("Google Chrome executable is unavailable")
        return {
            "execution_id": execution_id,
            "route": route,
            "screenshot_path": screenshot_path,
            "user_data_dir": user_data_dir,
            "profile_directory": profile_directory,
            "timeout_seconds": float(timeout),
        }

    def _launch(self, prepared: Mapping[str, Any]) -> subprocess.Popen:
        command = (
            str(self.chrome_executable),
            "--user-data-dir=%s" % prepared["user_data_dir"],
            "--profile-directory=%s" % prepared["profile_directory"],
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-pings",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost",
            str(prepared["route"]),
        )
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=self.start_new_session,
            close_fds=True,
        )

    @staticmethod
    def _page_endpoint(
        user_data_dir: Path,
        deadline: float,
        process: subprocess.Popen,
    ) -> str:
        port_file = user_data_dir / "DevToolsActivePort"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise BrowserCollectorError(
                    "visible Chrome exited before exposing its fixed page"
                )
            try:
                lines = port_file.read_text(encoding="ascii").splitlines()
                port = int(lines[0])
                if not 1 <= port <= 65535:
                    raise ValueError
                with urlopen(
                    "http://127.0.0.1:%d/json/list" % port,
                    timeout=max(0.1, deadline - time.monotonic()),
                ) as response:
                    targets = json.loads(response.read(1024 * 1024).decode("utf-8"))
                for target in targets:
                    if target.get("type") == "page" and isinstance(
                        target.get("webSocketDebuggerUrl"), str
                    ):
                        if process.poll() is not None:
                            raise BrowserCollectorError(
                                "visible Chrome did not own the page endpoint"
                            )
                        return target["webSocketDebuggerUrl"]
            except (OSError, ValueError, IndexError, KeyError, json.JSONDecodeError):
                pass
            time.sleep(0.05)
        raise BrowserCollectorError("visible Chrome did not expose its fixed page")

    def _page_state(
        self, connection: _CDPConnection, deadline: float
    ) -> Mapping[str, str]:
        while time.monotonic() < deadline:
            ready = connection.command(
                "Runtime.evaluate",
                {"expression": "document.readyState", "returnByValue": True},
            )
            if ready.get("result", {}).get("value") == "complete":
                state_result = connection.command(
                    "Runtime.evaluate",
                    {"expression": self._STATE_EXPRESSION, "returnByValue": True},
                )
                raw = state_result.get("result", {}).get("value")
                if not isinstance(raw, str) or len(raw) > 1024 * 1024:
                    raise BrowserCollectorError("Chrome returned invalid page state")
                try:
                    state = json.loads(raw)
                except json.JSONDecodeError as error:
                    raise BrowserCollectorError("Chrome returned invalid page state") from error
                if (
                    not isinstance(state, dict)
                    or set(state) != {"route", "title", "body"}
                    or any(not isinstance(value, str) for value in state.values())
                ):
                    raise BrowserCollectorError("Chrome returned invalid page state")
                return state
            time.sleep(0.05)
        raise BrowserCollectorError("visible Chrome did not finish loading")

    def _terminate_process(self, process: subprocess.Popen) -> None:
        if process.poll() is not None:
            process.wait()
            return
        if not self.start_new_session:
            process.terminate()
            try:
                process.wait(timeout=3)
                return
            except subprocess.TimeoutExpired:
                process.kill()
            try:
                process.wait(timeout=3)
                return
            except subprocess.TimeoutExpired as error:
                raise BrowserCollectorError(
                    "visible Chrome process did not stop"
                ) from error
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired as error:
            raise BrowserCollectorError(
                "visible Chrome process group did not stop"
            ) from error
