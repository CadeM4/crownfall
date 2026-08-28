#!/usr/bin/env python3
"""Disposable Crownfall target runtime.

This process is intentionally split in two.  The supervisor retains uid 0 and
exposes a small, fixed-operation keeper on a Unix socket.  Its child permanently
drops to uid/gid 10001 before opening the HTTP listener.

The target contains three deliberate defects for one bounded lab chain:

* HTTP authorization examines the raw request target while dispatch decodes and
  normalizes it.
* the bundle extractor validates member names lexically but never validates a
  symbolic link's target or resolves intermediate links before writing files.
* the keeper policy interprets the first duplicate JSON key while its backend
  interprets the last.

The keeper cannot execute commands, accept paths, or accept caller-controlled
proof content.  It can only create and remove a proof whose filename is derived
from a validated 32-hex nonce beneath the fixed root-only proof directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import errno
import hashlib
import hmac
import http.server
import io
import json
import os
import posixpath
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Final, Iterable


APP_UID: Final = 10001
APP_GID: Final = 10001

STATE_ROOT: Final = Path("/srv/crownfall")
STAGING_ROOT: Final = STATE_ROOT / "staging"
PLUGIN_ROOT: Final = STATE_ROOT / "plugins"
RESULT_ROOT: Final = STATE_ROOT / "results"
PROOF_ROOT: Final = STATE_ROOT / "proofs"
RUN_ROOT: Final = Path("/run/crownfall")
KEEPER_SOCKET: Final = RUN_ROOT / "keeper.sock"

PLUGIN_NAME: Final = "crown_probe.py"
PROTOCOL: Final = 1
SERVICE_NAME: Final = "crownfall-disposable-target"

MAX_RAW_TARGET: Final = 2048
MAX_JSON_BODY: Final = 4096
MAX_TAR_BODY: Final = 256 * 1024
MAX_TAR_MEMBERS: Final = 32
MAX_TAR_EXPANDED: Final = 192 * 1024
MAX_MEMBER_SIZE: Final = 128 * 1024
MAX_MEMBER_NAME: Final = 160
MAX_LINK_NAME: Final = 256
MAX_KEEPER_FRAME: Final = 4096
MAX_PLUGIN_OUTPUT: Final = 64 * 1024
PLUGIN_TIMEOUT_SECONDS: Final = 12.0

NONCE_RE: Final = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
LAB_ID_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")

RAW_ROUTE_PREFIX: Final = "/public/"
NORMAL_ROUTE_PREFIX: Final = "/internal/admin/"
NORMAL_ROUTES: Final = {
    "/internal/admin/bundle",
    "/internal/admin/activate",
    "/internal/admin/result",
    "/internal/admin/cleanup",
}


class TargetError(Exception):
    """Expected request or state failure with a stable public error code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail


class KeeperError(Exception):
    """Keeper-side validation failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True)
class Config:
    lab_id: str
    outer_key: bytes
    bind: str
    port: int
    clock_skew_seconds: int

    @property
    def target_fingerprint(self) -> str:
        material = b"crownfall-target-v1\x00" + self.lab_id.encode("ascii")
        return hmac.new(self.outer_key, material, hashlib.sha256).hexdigest()

    @classmethod
    def from_environment(cls, args: argparse.Namespace) -> "Config":
        lab_id = args.lab_id or os.environ.get("CROWNFALL_LAB_ID", "")
        key_hex = args.outer_key_hex or os.environ.get(
            "CROWNFALL_OUTER_KEY_HEX", ""
        )
        bind = args.bind or os.environ.get("CROWNFALL_BIND", "127.0.0.1")
        port_text = (
            str(args.port)
            if args.port is not None
            else os.environ.get("CROWNFALL_PORT", "8785")
        )

        if LAB_ID_RE.fullmatch(lab_id) is None:
            raise SystemExit(
                "CROWNFALL_LAB_ID must be 8-48 lowercase letters, digits, or hyphens"
            )
        if SHA256_RE.fullmatch(key_hex) is None:
            raise SystemExit("CROWNFALL_OUTER_KEY_HEX must be exactly 64 lowercase hex")
        try:
            port = int(port_text, 10)
        except ValueError as exc:
            raise SystemExit("CROWNFALL_PORT must be an integer") from exc
        if not 1 <= port <= 65535:
            raise SystemExit("CROWNFALL_PORT must be between 1 and 65535")
        if not 5 <= args.clock_skew <= 300:
            raise SystemExit("--clock-skew must be between 5 and 300 seconds")
        if "\x00" in bind or len(bind) > 255:
            raise SystemExit("invalid bind address")

        return cls(
            lab_id=lab_id,
            outer_key=bytes.fromhex(key_hex),
            bind=bind,
            port=port,
            clock_skew_seconds=args.clock_skew,
        )


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def mode_text(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def stat_evidence(path: Path, *, include_path: bool = True) -> dict[str, Any]:
    info = path.stat(follow_symlinks=False)
    evidence: dict[str, Any] = {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode_text(info.st_mode),
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }
    if include_path:
        evidence["path"] = str(path)
    return evidence


def regular_file_evidence(path: Path) -> dict[str, Any]:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise TargetError(409, "not_a_regular_file")
    if path.is_symlink():
        raise TargetError(409, "symbolic_file_rejected")
    data = path.read_bytes()
    evidence = stat_evidence(path)
    evidence.update(
        {
            "name": path.name,
            "sha256": sha256_bytes(data),
            "realpath": os.path.realpath(path),
        }
    )
    return evidence


def ensure_root_runtime() -> None:
    if sys.platform != "linux":
        raise SystemExit("crownfall-target requires Linux")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise SystemExit("crownfall-target must start as uid/gid 0")


def assert_fixed_child(parent: Path, child: Path) -> None:
    parent_real = os.path.realpath(parent)
    child_real = os.path.realpath(child)
    if os.path.commonpath([parent_real, child_real]) != parent_real:
        raise RuntimeError(f"state path escaped fixed root: {child}")
    if child_real == parent_real:
        raise RuntimeError(f"refusing operation on state root: {child}")


def remove_tree_exact(path: Path, parent: Path) -> None:
    """Remove one fixed directory without ever following a root symlink."""

    assert_fixed_child(parent, path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"refusing symlink at fixed state path: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory at fixed state path: {path}")
    shutil.rmtree(path)


def make_owned_directory(path: Path, uid: int, gid: int, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=False)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def prepare_layout() -> None:
    """Create a deterministic, empty state tree before privileges are dropped."""

    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    root_info = STATE_ROOT.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError(f"invalid state root: {STATE_ROOT}")
    os.chown(STATE_ROOT, 0, 0)
    os.chmod(STATE_ROOT, 0o755)

    for fixed in (STAGING_ROOT, PLUGIN_ROOT, RESULT_ROOT, PROOF_ROOT):
        remove_tree_exact(fixed, STATE_ROOT)

    make_owned_directory(STAGING_ROOT, APP_UID, APP_GID, 0o700)
    make_owned_directory(PLUGIN_ROOT, APP_UID, APP_GID, 0o700)
    make_owned_directory(RESULT_ROOT, 0, APP_GID, 0o750)
    make_owned_directory(PROOF_ROOT, 0, 0, 0o700)

    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    run_info = RUN_ROOT.lstat()
    if stat.S_ISLNK(run_info.st_mode) or not stat.S_ISDIR(run_info.st_mode):
        raise RuntimeError(f"invalid runtime root: {RUN_ROOT}")
    os.chown(RUN_ROOT, 0, APP_GID)
    os.chmod(RUN_ROOT, 0o750)
    try:
        socket_info = KEEPER_SOCKET.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(socket_info.st_mode):
            raise RuntimeError(f"refusing to replace non-socket: {KEEPER_SOCKET}")
        KEEPER_SOCKET.unlink()


def atomic_write_root_file(directory: Path, name: str, body: bytes, mode: int) -> Path:
    """Write beneath a root-owned fixed directory using dirfd-relative calls."""

    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary_name = f".{name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    file_fd = -1
    try:
        file_fd = os.open(temporary_name, flags, mode, dir_fd=directory_fd)
        view = memoryview(body)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short proof write")
            view = view[written:]
        os.fsync(file_fd)
        os.fchmod(file_fd, mode)
        os.close(file_fd)
        file_fd = -1
        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except BaseException:
        if file_fd >= 0:
            os.close(file_fd)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory_fd)
    return directory / name


def unlink_root_file(directory: Path, name: str) -> bool:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode):
            raise KeeperError("state_file_not_regular")
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    finally:
        os.close(directory_fd)


def recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise KeeperError("truncated_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_keeper_frame(connection: socket.socket) -> bytes:
    header = recv_exact(connection, 4)
    (length,) = struct.unpack("!I", header)
    if length < 2 or length > MAX_KEEPER_FRAME:
        raise KeeperError("invalid_frame_length")
    return recv_exact(connection, length)


def send_keeper_frame(connection: socket.socket, value: dict[str, Any]) -> None:
    payload = canonical_json_bytes(value)
    if len(payload) > MAX_KEEPER_FRAME:
        payload = canonical_json_bytes({"ok": False, "error": "response_too_large"})
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def parse_keeper_request(raw: bytes, expected_lab_id: str) -> dict[str, Any]:
    """Apply the deliberately divergent policy and backend interpretations."""

    try:
        text = raw.decode("utf-8", "strict")
        pairs = json.loads(text, object_pairs_hook=lambda value: value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeeperError("invalid_json") from exc
    if not isinstance(pairs, list) or any(
        not isinstance(pair, tuple) or len(pair) != 2 for pair in pairs
    ):
        raise KeeperError("request_must_be_object")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in pairs):
        raise KeeperError("string_fields_required")

    allowed = {"role", "op", "lab_id", "proof_nonce", "plugin_sha256"}
    keys = [key for key, _ in pairs]
    if set(keys) - allowed:
        raise KeeperError("unknown_field")
    counts = Counter(keys)
    if any(counts[key] != 1 for key in allowed - {"role"}):
        raise KeeperError("missing_or_duplicate_field")
    if counts["role"] not in (1, 2):
        raise KeeperError("invalid_role_count")

    # Policy construction keeps the first appearance of each key.
    first_wins: dict[str, str] = {}
    for key, value in pairs:
        first_wins.setdefault(key, value)
    if first_wins["role"] != "guest":
        raise KeeperError("policy_role_denied")
    if first_wins["op"] not in {"write_proof", "delete_proof"}:
        raise KeeperError("operation_denied")
    if first_wins["lab_id"] != expected_lab_id:
        raise KeeperError("lab_mismatch")
    if NONCE_RE.fullmatch(first_wins["proof_nonce"]) is None:
        raise KeeperError("invalid_proof_nonce")
    if SHA256_RE.fullmatch(first_wins["plugin_sha256"]) is None:
        raise KeeperError("invalid_plugin_sha256")

    # The backend uses ordinary json.loads semantics: the last duplicate wins.
    backend = json.loads(text)
    if backend.get("role") != "admin":
        raise KeeperError("backend_role_denied")
    if backend.get("op") != first_wins["op"]:
        raise KeeperError("operation_differential_denied")
    for field in ("lab_id", "proof_nonce", "plugin_sha256"):
        if backend.get(field) != first_wins[field]:
            raise KeeperError("field_differential_denied")

    return {
        "op": first_wins["op"],
        "lab_id": first_wins["lab_id"],
        "proof_nonce": first_wins["proof_nonce"],
        "plugin_sha256": first_wins["plugin_sha256"],
        "first_role": first_wins["role"],
        "last_role": backend["role"],
        "role_occurrences": counts["role"],
    }


class RootKeeper:
    def __init__(self, config: Config, listener: socket.socket) -> None:
        self.config = config
        self.listener = listener
        self.stop_event = threading.Event()

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_event.set()

    def proof_filename(self, proof_nonce: str) -> str:
        return f"{proof_nonce}.proof"

    def result_filename(self, proof_nonce: str) -> str:
        return f"{proof_nonce}.json"

    def write_proof(
        self, request: dict[str, Any], peer: dict[str, int]
    ) -> dict[str, Any]:
        proof_nonce = request["proof_nonce"]
        proof_name = self.proof_filename(proof_nonce)
        result_name = self.result_filename(proof_nonce)
        proof_path = PROOF_ROOT / proof_name
        result_path = RESULT_ROOT / result_name
        if proof_path.exists() or result_path.exists():
            raise KeeperError("proof_already_exists")

        created_at = utc_now()
        proof_record = {
            "schema": 1,
            "service": SERVICE_NAME,
            "lab_id": self.config.lab_id,
            "proof_nonce": proof_nonce,
            "plugin_sha256": request["plugin_sha256"],
            "created_at": created_at,
            "keeper_pid": os.getpid(),
            "keeper_uid": os.getuid(),
            "keeper_euid": os.geteuid(),
        }
        proof_bytes = canonical_json_bytes(proof_record)
        atomic_write_root_file(PROOF_ROOT, proof_name, proof_bytes, 0o600)

        proof = stat_evidence(proof_path)
        proof.update(
            {
                "name": proof_name,
                "sha256": sha256_bytes(proof_bytes),
            }
        )
        root_parent = stat_evidence(PROOF_ROOT)
        keeper = {
            "pid": os.getpid(),
            "uid": os.getuid(),
            "euid": os.geteuid(),
            "gid": os.getgid(),
            "egid": os.getegid(),
        }
        result: dict[str, Any] = {
            "ok": True,
            "schema": 1,
            "operation": "write_proof",
            "lab_id": self.config.lab_id,
            "proof_nonce": proof_nonce,
            "plugin_sha256": request["plugin_sha256"],
            "created_at": created_at,
            "keeper": keeper,
            "peer": peer,
            "policy": {
                "first_role": request["first_role"],
                "backend_role": request["last_role"],
                "role_occurrences": request["role_occurrences"],
            },
            "root_parent": root_parent,
            "proof": proof,
        }
        result_bytes = canonical_json_bytes(result)
        if len(result_bytes) > MAX_KEEPER_FRAME:
            unlink_root_file(PROOF_ROOT, proof_name)
            raise KeeperError("result_too_large")
        atomic_write_root_file(RESULT_ROOT, result_name, result_bytes, 0o640)
        os.chown(result_path, 0, APP_GID, follow_symlinks=False)
        result["result_file"] = stat_evidence(result_path)
        # The stored result deliberately omits its own post-write stat; the
        # response may include it without introducing a recursive hash.
        return result

    def delete_proof(
        self, request: dict[str, Any], peer: dict[str, int]
    ) -> dict[str, Any]:
        proof_nonce = request["proof_nonce"]
        proof_name = self.proof_filename(proof_nonce)
        result_name = self.result_filename(proof_nonce)
        proof_path = PROOF_ROOT / proof_name
        result_path = RESULT_ROOT / result_name

        try:
            proof_bytes = proof_path.read_bytes()
            proof_record = json.loads(proof_bytes)
        except FileNotFoundError as exc:
            raise KeeperError("proof_not_found") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise KeeperError("proof_state_invalid") from exc
        if not isinstance(proof_record, dict):
            raise KeeperError("proof_state_invalid")
        if (
            proof_record.get("lab_id") != self.config.lab_id
            or proof_record.get("proof_nonce") != proof_nonce
            or proof_record.get("plugin_sha256") != request["plugin_sha256"]
        ):
            raise KeeperError("proof_identity_mismatch")

        before = stat_evidence(proof_path)
        before["sha256"] = sha256_bytes(proof_bytes)
        proof_deleted = unlink_root_file(PROOF_ROOT, proof_name)
        result_deleted = unlink_root_file(RESULT_ROOT, result_name)
        return {
            "ok": True,
            "schema": 1,
            "operation": "delete_proof",
            "lab_id": self.config.lab_id,
            "proof_nonce": proof_nonce,
            "plugin_sha256": request["plugin_sha256"],
            "completed_at": utc_now(),
            "keeper": {
                "pid": os.getpid(),
                "uid": os.getuid(),
                "euid": os.geteuid(),
                "gid": os.getgid(),
                "egid": os.getegid(),
            },
            "peer": peer,
            "policy": {
                "first_role": request["first_role"],
                "backend_role": request["last_role"],
                "role_occurrences": request["role_occurrences"],
            },
            "proof_before": before,
            "deleted": {"proof": proof_deleted, "result": result_deleted},
            "proof_exists_after": proof_path.exists(),
            "result_exists_after": result_path.exists(),
        }

    def handle_connection(self, connection: socket.socket) -> None:
        connection.settimeout(3.0)
        try:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
            peer = {"pid": peer_pid, "uid": peer_uid, "gid": peer_gid}
            if peer_uid != APP_UID or peer_gid != APP_GID:
                raise KeeperError("peer_identity_denied")
            raw = receive_keeper_frame(connection)
            request = parse_keeper_request(raw, self.config.lab_id)
            if request["op"] == "write_proof":
                response = self.write_proof(request, peer)
            elif request["op"] == "delete_proof":
                response = self.delete_proof(request, peer)
            else:
                raise KeeperError("operation_denied")
        except KeeperError as exc:
            response = {"ok": False, "error": exc.code}
        except (OSError, ValueError, TypeError):
            response = {"ok": False, "error": "keeper_io_failure"}
        try:
            send_keeper_frame(connection, response)
        except OSError:
            pass

    def serve(self, child_pid: int) -> int:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        self.listener.settimeout(0.25)
        child_status: int | None = None
        try:
            while not self.stop_event.is_set():
                waited, status = os.waitpid(child_pid, os.WNOHANG)
                if waited == child_pid:
                    child_status = status
                    self.stop_event.set()
                    break
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self.stop_event.is_set():
                        break
                    raise RuntimeError("keeper accept failed") from exc
                with connection:
                    self.handle_connection(connection)
        finally:
            if child_status is None:
                try:
                    os.kill(child_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    waited, status = os.waitpid(child_pid, os.WNOHANG)
                    if waited == child_pid:
                        child_status = status
                        break
                    time.sleep(0.05)
                if child_status is None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _, child_status = os.waitpid(child_pid, 0)
            self.listener.close()
            try:
                socket_info = KEEPER_SOCKET.lstat()
                if stat.S_ISSOCK(socket_info.st_mode):
                    KEEPER_SOCKET.unlink()
            except FileNotFoundError:
                pass

        if os.WIFEXITED(child_status):
            return os.WEXITSTATUS(child_status)
        return 128 + os.WTERMSIG(child_status)


class ReplayWindow:
    def __init__(self, skew_seconds: int) -> None:
        self.skew_seconds = skew_seconds
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}

    def accept(self, nonce: str, request_time: int, now: int) -> bool:
        with self._lock:
            oldest = now - (self.skew_seconds * 2)
            self._seen = {
                key: value for key, value in self._seen.items() if value >= oldest
            }
            if nonce in self._seen:
                return False
            self._seen[nonce] = request_time
            return True


@dataclasses.dataclass(frozen=True)
class AuthorizedRequest:
    raw_target: str
    normalized_path: str
    query: dict[str, list[str]]
    body: bytes


class CrownfallHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 32

    def __init__(self, address: tuple[str, int], config: Config) -> None:
        super().__init__(address, CrownfallHandler, bind_and_activate=False)
        self.config = config
        self.replay = ReplayWindow(config.clock_skew_seconds)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_bind()
        self.server_activate()


class CrownfallHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "crownfall"
    sys_version = ""

    @property
    def target_server(self) -> CrownfallHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: Any) -> None:
        message = fmt % args
        print(
            json.dumps(
                {
                    "time": utc_now(),
                    "component": "http",
                    "peer": self.client_address[0],
                    "message": message,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )

    def send_json(self, status_code: int, value: dict[str, Any]) -> None:
        body = canonical_json_bytes(value)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def error_json(self, exc: TargetError) -> None:
        response: dict[str, Any] = {"ok": False, "error": exc.code}
        if exc.detail:
            response["detail"] = exc.detail
        self.send_json(exc.status, response)

    def do_GET(self) -> None:  # noqa: N802
        try:
            if urllib.parse.urlsplit(self.path).path == "/manifest":
                self.require_empty_body()
                self.handle_manifest()
                return
            request = self.authorize_exploit_request("GET")
            if request.normalized_path != "/internal/admin/result":
                raise TargetError(404, "route_not_found")
            self.handle_result(request)
        except TargetError as exc:
            self.error_json(exc)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_manifest(self) -> None:
        parts = urllib.parse.urlsplit(self.path)
        if parts.scheme or parts.netloc or parts.fragment or parts.path != "/manifest":
            raise TargetError(400, "invalid_manifest_request")
        try:
            query = urllib.parse.parse_qs(
                parts.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=1,
            )
        except ValueError as exc:
            raise TargetError(400, "invalid_manifest_query") from exc
        if set(query) != {"challenge"} or len(query["challenge"]) != 1:
            raise TargetError(400, "manifest_challenge_required")
        challenge = query["challenge"][0]
        if NONCE_RE.fullmatch(challenge) is None:
            raise TargetError(400, "invalid_manifest_challenge")
        config = self.target_server.config
        fingerprint = config.target_fingerprint
        attestation_material = (
            b"crownfall-manifest-v1\x00"
            + challenge.encode("ascii")
            + b"\x00"
            + config.lab_id.encode("ascii")
            + b"\x00"
            + fingerprint.encode("ascii")
            + b"\x00"
            + b"1"
        )
        attestation_mac = hmac.new(
            config.outer_key, attestation_material, hashlib.sha256
        ).hexdigest()
        self.send_json(
            200,
            {
                "service": SERVICE_NAME,
                "protocol": PROTOCOL,
                "lab_id": config.lab_id,
                "target_fingerprint": fingerprint,
                "challenge": challenge,
                "attestation_mac": attestation_mac,
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        try:
            request = self.authorize_exploit_request("POST")
            if request.normalized_path == "/internal/admin/bundle":
                self.handle_bundle(request)
            elif request.normalized_path == "/internal/admin/activate":
                self.handle_activate(request)
            elif request.normalized_path == "/internal/admin/cleanup":
                self.handle_cleanup(request)
            else:
                raise TargetError(404, "route_not_found")
        except TargetError as exc:
            self.error_json(exc)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_PUT(self) -> None:  # noqa: N802
        self.send_json(405, {"ok": False, "error": "method_not_allowed"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_OPTIONS = do_PUT

    def require_empty_body(self) -> None:
        if self.headers.get("Transfer-Encoding") is not None:
            raise TargetError(400, "transfer_encoding_rejected")
        value = self.headers.get("Content-Length")
        if value not in (None, "0"):
            raise TargetError(400, "body_not_allowed")

    def read_body(self, maximum: int) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise TargetError(400, "transfer_encoding_rejected")
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            raise TargetError(411, "single_content_length_required")
        try:
            length = int(lengths[0], 10)
        except ValueError as exc:
            raise TargetError(400, "invalid_content_length") from exc
        if length < 0 or length > maximum:
            raise TargetError(413, "body_too_large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise TargetError(400, "truncated_body")
        return body

    def parse_raw_target(self) -> tuple[str, str, dict[str, list[str]]]:
        raw_target = self.path
        if len(raw_target) > MAX_RAW_TARGET or not raw_target.startswith("/"):
            raise TargetError(400, "invalid_request_target")
        if any(ord(character) < 0x20 for character in raw_target):
            raise TargetError(400, "invalid_request_target")
        parts = urllib.parse.urlsplit(raw_target)
        if parts.scheme or parts.netloc or parts.fragment:
            raise TargetError(400, "origin_form_required")
        try:
            decoded_path = urllib.parse.unquote(parts.path, errors="strict")
        except UnicodeDecodeError as exc:
            raise TargetError(400, "invalid_path_encoding") from exc
        if "\x00" in decoded_path or "\\" in decoded_path:
            raise TargetError(400, "invalid_decoded_path")
        normalized = posixpath.normpath(decoded_path)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        try:
            query = urllib.parse.parse_qs(
                parts.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
        except ValueError as exc:
            raise TargetError(400, "invalid_query") from exc
        return raw_target, normalized, query

    def authorize_exploit_request(self, method: str) -> AuthorizedRequest:
        raw_target, normalized, query = self.parse_raw_target()

        # Deliberate flaw: policy checks only the raw target.  Dispatch below
        # uses the decoded, normalized path.
        raw_path = urllib.parse.urlsplit(raw_target).path
        if raw_path.startswith(NORMAL_ROUTE_PREFIX):
            raise TargetError(403, "direct_admin_path_denied")
        if not raw_path.startswith(RAW_ROUTE_PREFIX):
            raise TargetError(403, "raw_path_policy_denied")
        if normalized not in NORMAL_ROUTES:
            raise TargetError(404, "route_not_found")

        role_values = self.headers.get_all("X-Application-Role", failobj=[])
        if role_values != ["guest"]:
            raise TargetError(403, "application_role_denied")

        if method == "GET":
            self.require_empty_body()
            body = b""
        else:
            maximum = (
                MAX_TAR_BODY
                if normalized == "/internal/admin/bundle"
                else MAX_JSON_BODY
            )
            body = self.read_body(maximum)

        config = self.target_server.config
        lab_values = self.headers.get_all("X-Crownfall-Lab", failobj=[])
        time_values = self.headers.get_all("X-Crownfall-Time", failobj=[])
        nonce_values = self.headers.get_all("X-Crownfall-Nonce", failobj=[])
        mac_values = self.headers.get_all("X-Crownfall-Mac", failobj=[])
        if not all(len(values) == 1 for values in (lab_values, time_values, nonce_values, mac_values)):
            raise TargetError(401, "signature_headers_required")
        lab_id, time_text, request_nonce, supplied_mac = (
            lab_values[0],
            time_values[0],
            nonce_values[0],
            mac_values[0],
        )
        if lab_id != config.lab_id:
            raise TargetError(401, "lab_mismatch")
        if NONCE_RE.fullmatch(request_nonce) is None:
            raise TargetError(401, "invalid_request_nonce")
        if SHA256_RE.fullmatch(supplied_mac) is None:
            raise TargetError(401, "invalid_mac")
        if not time_text.isascii() or not time_text.isdecimal() or len(time_text) > 12:
            raise TargetError(401, "invalid_request_time")
        request_time = int(time_text, 10)
        now = int(time.time())
        if abs(now - request_time) > config.clock_skew_seconds:
            raise TargetError(401, "request_time_outside_window")

        body_hash = sha256_bytes(body)
        canonical = (
            f"{method.upper()}\n{raw_target}\n{lab_id}\n{time_text}\n"
            f"{request_nonce}\n{body_hash}"
        ).encode("utf-8")
        expected_mac = hmac.new(config.outer_key, canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise TargetError(401, "mac_mismatch")
        if not self.target_server.replay.accept(request_nonce, request_time, now):
            raise TargetError(409, "request_replayed")

        return AuthorizedRequest(
            raw_target=raw_target,
            normalized_path=normalized,
            query=query,
            body=body,
        )

    def require_content_type(self, expected: str) -> None:
        values = self.headers.get_all("Content-Type", failobj=[])
        if len(values) != 1 or values[0].split(";", 1)[0].strip().lower() != expected:
            raise TargetError(415, "unsupported_content_type")

    def parse_json_body(self, request: AuthorizedRequest) -> dict[str, Any]:
        self.require_content_type("application/json")
        try:
            value = json.loads(request.body.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TargetError(400, "invalid_json") from exc
        if not isinstance(value, dict):
            raise TargetError(400, "json_object_required")
        return value

    def handle_bundle(self, request: AuthorizedRequest) -> None:
        self.require_content_type("application/x-tar")
        if not request.body:
            raise TargetError(400, "empty_bundle")
        plugin_path = PLUGIN_ROOT / PLUGIN_NAME
        if plugin_path.exists() or plugin_path.is_symlink():
            raise TargetError(409, "plugin_already_present", "run cleanup first")
        reset_staging_as_app()
        try:
            members = extract_deliberately_unsafe_tar(request.body)
            if not plugin_path.exists():
                raise TargetError(422, "plugin_not_landed")
            plugin = regular_file_evidence(plugin_path)
            landing = next(
                (
                    member
                    for member in members
                    if member["type"] == "regular"
                    and member["realpath_after"] == str(plugin_path)
                ),
                None,
            )
            if landing is None:
                raise TargetError(409, "plugin_landing_evidence_missing")
            plugin.update(
                {
                    "archive_member": landing["name"],
                    "lexical_archive_path": landing["lexical_path"],
                    "archive_realpath": landing["realpath_after"],
                    "symlink_followed": landing["lexical_path"]
                    != landing["realpath_after"],
                    "landed_outside_staging": os.path.commonpath(
                        [str(STAGING_ROOT), landing["realpath_after"]]
                    )
                    != str(STAGING_ROOT),
                }
            )
            if plugin["uid"] != APP_UID or plugin["gid"] != APP_GID:
                raise TargetError(409, "plugin_owner_invalid")
        except Exception:
            # The upload began from an empty plugin directory.  If extraction
            # fails after following a link, remove every application-owned
            # plugin artifact before exposing the error.
            reset_staging_as_app()
            reset_plugin_root_as_app()
            raise
        self.send_json(
            201,
            {
                "ok": True,
                "stage": "bundle",
                "bundle_sha256": sha256_bytes(request.body),
                "bundle_size": len(request.body),
                "members": members,
                "plugin": plugin,
                "completed_at": utc_now(),
            },
        )

    def handle_activate(self, request: AuthorizedRequest) -> None:
        value = self.parse_json_body(request)
        required = {"plugin_name", "plugin_sha256", "proof_nonce"}
        if set(value) != required:
            raise TargetError(400, "activation_fields_invalid")
        if value["plugin_name"] != PLUGIN_NAME:
            raise TargetError(400, "plugin_name_denied")
        plugin_sha256 = value["plugin_sha256"]
        proof_nonce = value["proof_nonce"]
        if not isinstance(plugin_sha256, str) or SHA256_RE.fullmatch(plugin_sha256) is None:
            raise TargetError(400, "invalid_plugin_sha256")
        if not isinstance(proof_nonce, str) or NONCE_RE.fullmatch(proof_nonce) is None:
            raise TargetError(400, "invalid_proof_nonce")

        plugin_path = PLUGIN_ROOT / PLUGIN_NAME
        plugin = regular_file_evidence(plugin_path)
        if plugin["sha256"] != plugin_sha256:
            raise TargetError(409, "plugin_hash_mismatch")
        if plugin["size"] > MAX_MEMBER_SIZE:
            raise TargetError(409, "plugin_too_large")
        if os.path.realpath(plugin_path) != str(plugin_path):
            raise TargetError(409, "plugin_realpath_invalid")
        result_path = RESULT_ROOT / f"{proof_nonce}.json"
        if result_path.exists():
            raise TargetError(409, "result_already_exists")

        direct_control = direct_proof_write_control(proof_nonce)
        execution = execute_plugin(plugin_path, plugin_sha256, proof_nonce)
        result = read_keeper_result(proof_nonce, plugin_sha256)
        verify_plugin_report(execution["report"], proof_nonce, plugin_sha256, result)

        self.send_json(
            200,
            {
                "ok": True,
                "stage": "activate",
                "plugin": plugin,
                "direct_write_control": direct_control,
                "execution": execution,
                "result": result,
                "completed_at": utc_now(),
            },
        )

    def handle_result(self, request: AuthorizedRequest) -> None:
        if set(request.query) != {"proof_nonce"} or len(request.query["proof_nonce"]) != 1:
            raise TargetError(400, "proof_nonce_query_required")
        proof_nonce = request.query["proof_nonce"][0]
        if NONCE_RE.fullmatch(proof_nonce) is None:
            raise TargetError(400, "invalid_proof_nonce")
        result_path = RESULT_ROOT / f"{proof_nonce}.json"
        try:
            result_bytes = result_path.read_bytes()
        except FileNotFoundError as exc:
            raise TargetError(404, "result_not_found") from exc
        info = result_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != APP_GID
            or stat.S_IMODE(info.st_mode) != 0o640
        ):
            raise TargetError(409, "result_state_invalid")
        try:
            result = json.loads(result_bytes)
        except json.JSONDecodeError as exc:
            raise TargetError(409, "result_state_invalid") from exc
        if not isinstance(result, dict) or result.get("proof_nonce") != proof_nonce:
            raise TargetError(409, "result_identity_invalid")
        result_file = stat_evidence(result_path)
        result_file["sha256"] = sha256_bytes(result_bytes)
        self.send_json(
            200,
            {
                "ok": True,
                "stage": "result",
                "result_file": result_file,
                "result": result,
            },
        )

    def handle_cleanup(self, request: AuthorizedRequest) -> None:
        value = self.parse_json_body(request)
        if set(value) != {"proof_nonce", "plugin_sha256"}:
            raise TargetError(400, "cleanup_fields_invalid")
        proof_nonce = value["proof_nonce"]
        plugin_sha256 = value["plugin_sha256"]
        if not isinstance(proof_nonce, str) or NONCE_RE.fullmatch(proof_nonce) is None:
            raise TargetError(400, "invalid_proof_nonce")
        if not isinstance(plugin_sha256, str) or SHA256_RE.fullmatch(plugin_sha256) is None:
            raise TargetError(400, "invalid_plugin_sha256")

        keeper_failure: TargetError | None = None
        try:
            keeper = call_keeper(
                duplicate_keeper_json(
                    operation="delete_proof",
                    lab_id=self.target_server.config.lab_id,
                    proof_nonce=proof_nonce,
                    plugin_sha256=plugin_sha256,
                )
            )
        except TargetError as exc:
            keeper_failure = exc
            keeper = {"ok": False, "error": exc.code}
        # Application-owned artifacts are cleared even if an earlier stage
        # failed before the keeper created a proof.  A successful proof run
        # still requires the full keeper deletion evidence below.
        plugin_removed = remove_plugin_as_app(plugin_sha256)
        extra_plugins_removed = reset_plugin_root_as_app()
        staging_removed = reset_staging_as_app()
        if keeper_failure is not None:
            raise keeper_failure
        if not keeper.get("ok"):
            code = keeper.get("error", "cleanup_keeper_denied")
            if code == "proof_not_found":
                self.send_json(
                    200,
                    {
                        "ok": True,
                        "stage": "cleanup",
                        "keeper": keeper,
                        "partial_run": True,
                        "removed": {
                            "plugin": plugin_removed,
                            "extra_plugin_entries": extra_plugins_removed,
                            "staging_entries": staging_removed,
                        },
                        "result_absent": not (
                            RESULT_ROOT / f"{proof_nonce}.json"
                        ).exists(),
                        "completed_at": utc_now(),
                    },
                )
                return
            raise TargetError(409, str(code))
        result_absent = not (RESULT_ROOT / f"{proof_nonce}.json").exists()
        if (
            keeper.get("proof_exists_after") is not False
            or keeper.get("result_exists_after") is not False
            or not result_absent
        ):
            raise TargetError(500, "cleanup_verification_failed")
        self.send_json(
            200,
            {
                "ok": True,
                "stage": "cleanup",
                "keeper": keeper,
                "removed": {
                    "plugin": plugin_removed,
                    "extra_plugin_entries": extra_plugins_removed,
                    "staging_entries": staging_removed,
                },
                "result_absent": result_absent,
                "completed_at": utc_now(),
            },
        )


def validate_member_name(name: str) -> PurePosixPath:
    if not name or len(name) > MAX_MEMBER_NAME or "\x00" in name or "\\" in name:
        raise TargetError(422, "invalid_member_name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise TargetError(422, "invalid_member_name")
    return path


def lexical_destination(member_path: PurePosixPath) -> Path:
    destination = Path(os.path.abspath(STAGING_ROOT.joinpath(*member_path.parts)))
    if os.path.commonpath([str(STAGING_ROOT), str(destination)]) != str(STAGING_ROOT):
        raise TargetError(422, "member_path_escaped")
    return destination


def extract_deliberately_unsafe_tar(body: bytes) -> list[dict[str, Any]]:
    """Extract a bounded tar while intentionally ignoring symlink targets.

    Member *names* receive strict lexical validation.  Symlink ``linkname``
    values do not receive containment validation, and regular-file writes use
    normal path opens that follow intermediate symlinks.  That mismatch is the
    intended bundle stage of this target.
    """

    try:
        archive = tarfile.open(fileobj=io.BytesIO(body), mode="r:")
    except tarfile.TarError as exc:
        raise TargetError(422, "invalid_uncompressed_tar") from exc
    with archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_TAR_MEMBERS:
            raise TargetError(422, "invalid_member_count")
        expected_names = ["notes", "bridge", "bridge/crown_probe.py"]
        expected_types = [tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.REGTYPE]
        if [member.name.rstrip("/") for member in members] != expected_names or [
            member.type for member in members
        ] != expected_types:
            raise TargetError(422, "unexpected_bundle_layout")
        expanded = sum(member.size for member in members if member.isreg())
        if expanded > MAX_TAR_EXPANDED:
            raise TargetError(422, "bundle_expands_too_large")

        evidence: list[dict[str, Any]] = []
        for member in members:
            member_path = validate_member_name(member.name)
            destination = lexical_destination(member_path)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if member.isdir():
                destination.mkdir(exist_ok=True, mode=0o700)
                kind = "directory"
            elif member.issym():
                if (
                    not member.linkname
                    or len(member.linkname) > MAX_LINK_NAME
                    or "\x00" in member.linkname
                ):
                    raise TargetError(422, "invalid_link_name")
                if destination.exists() or destination.is_symlink():
                    raise TargetError(422, "member_destination_exists")
                # Deliberate defect: linkname is neither normalized nor checked
                # against STAGING_ROOT.
                os.symlink(member.linkname, destination)
                kind = "symlink"
            elif member.isreg():
                if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                    raise TargetError(422, "member_too_large")
                source = archive.extractfile(member)
                if source is None:
                    raise TargetError(422, "member_data_missing")
                data = source.read(MAX_MEMBER_SIZE + 1)
                if len(data) != member.size or len(data) > MAX_MEMBER_SIZE:
                    raise TargetError(422, "member_size_mismatch")
                try:
                    with destination.open("xb") as output:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                    os.chmod(destination, 0o600)
                except FileExistsError as exc:
                    raise TargetError(422, "member_destination_exists") from exc
                kind = "regular"
            else:
                raise TargetError(422, "member_type_denied")

            item: dict[str, Any] = {
                "name": member.name,
                "type": kind,
                "lexical_path": str(destination),
                "realpath_after": os.path.realpath(destination),
            }
            if member.issym():
                item["linkname"] = member.linkname
            if member.isreg():
                item["size"] = member.size
                item["sha256"] = sha256_bytes(data)
            evidence.append(item)
        landed_path = Path(evidence[-1]["realpath_after"])
        if landed_path != PLUGIN_ROOT / PLUGIN_NAME:
            # The target check occurs only after the unsafe open has followed
            # the intermediate link.  Remove that newly created regular file
            # before failing so a malformed lab bundle cannot leave debris.
            try:
                landed_info = landed_path.lstat()
                if stat.S_ISREG(landed_info.st_mode) and landed_info.st_uid == APP_UID:
                    landed_path.unlink()
            except FileNotFoundError:
                pass
            raise TargetError(422, "plugin_landed_at_unexpected_path")
        return evidence


def reset_staging_as_app() -> int:
    if os.geteuid() != APP_UID or os.getegid() != APP_GID:
        raise RuntimeError("staging reset must run as application identity")
    root_info = STAGING_ROOT.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise TargetError(500, "staging_root_invalid")
    removed = 0
    for entry in list(os.scandir(STAGING_ROOT)):
        path = Path(entry.path)
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            path.unlink()
        else:
            shutil.rmtree(path)
        removed += 1
    return removed


def reset_plugin_root_as_app() -> int:
    if os.geteuid() != APP_UID or os.getegid() != APP_GID:
        raise RuntimeError("plugin reset must run as application identity")
    root_info = PLUGIN_ROOT.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise TargetError(500, "plugin_root_invalid")
    removed = 0
    for entry in list(os.scandir(PLUGIN_ROOT)):
        path = Path(entry.path)
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            path.unlink()
        else:
            shutil.rmtree(path)
        removed += 1
    return removed


def direct_proof_write_control(proof_nonce: str) -> dict[str, Any]:
    path = PROOF_ROOT / f"{proof_nonce}.proof"
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
    except PermissionError as exc:
        return {
            "attempted": True,
            "allowed": False,
            "errno": exc.errno,
            "error": errno.errorcode.get(exc.errno or 0, "EUNKNOWN"),
            "application_euid": os.geteuid(),
            "application_egid": os.getegid(),
            "path": str(path),
            "root_parent": stat_evidence(PROOF_ROOT),
        }
    except OSError as exc:
        raise TargetError(500, "direct_write_control_unexpected", str(exc.errno)) from exc
    else:
        os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise TargetError(500, "root_boundary_failed")


def duplicate_keeper_json(
    *, operation: str, lab_id: str, proof_nonce: str, plugin_sha256: str
) -> bytes:
    # Manual construction preserves the duplicate role keys by design.  All
    # interpolated values have already passed narrow ASCII regular expressions.
    text = (
        '{"role":"guest","op":"'
        + operation
        + '","lab_id":"'
        + lab_id
        + '","proof_nonce":"'
        + proof_nonce
        + '","plugin_sha256":"'
        + plugin_sha256
        + '","role":"admin"}'
    )
    return text.encode("ascii")


def call_keeper(raw_json: bytes) -> dict[str, Any]:
    if not 2 <= len(raw_json) <= MAX_KEEPER_FRAME:
        raise TargetError(500, "keeper_request_size_invalid")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(3.0)
    try:
        connection.connect(str(KEEPER_SOCKET))
        connection.sendall(struct.pack("!I", len(raw_json)) + raw_json)
        response_raw = receive_keeper_frame(connection)
    except (OSError, KeeperError) as exc:
        raise TargetError(502, "keeper_unavailable") from exc
    finally:
        connection.close()
    try:
        response = json.loads(response_raw)
    except json.JSONDecodeError as exc:
        raise TargetError(502, "keeper_response_invalid") from exc
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise TargetError(502, "keeper_response_invalid")
    return response


def plugin_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_PLUGIN_OUTPUT,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    os.umask(0o077)


def execute_plugin(
    plugin_path: Path, plugin_sha256: str, proof_nonce: str
) -> dict[str, Any]:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1",
        "CROWNFALL_KEEPER_SOCKET": str(KEEPER_SOCKET),
        "CROWNFALL_LAB_ID": os.environ["CROWNFALL_LAB_ID"],
        "CROWNFALL_PROOF_NONCE": proof_nonce,
        "CROWNFALL_PLUGIN_SHA256": plugin_sha256,
        "CROWNFALL_PROOF_PATH": str(PROOF_ROOT / f"{proof_nonce}.proof"),
    }
    started_ns = time.time_ns()
    started = time.monotonic()
    with tempfile.TemporaryFile(dir=STAGING_ROOT) as stdout_file, tempfile.TemporaryFile(
        dir=STAGING_ROOT
    ) as stderr_file:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--plugin-launcher",
                str(plugin_path),
            ],
            cwd=str(PLUGIN_ROOT),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
            close_fds=True,
        )
        try:
            return_code = process.wait(timeout=PLUGIN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise TargetError(504, "plugin_timed_out") from exc
        duration_ms = round((time.monotonic() - started) * 1000.0, 3)
        if stdout_file.tell() > MAX_PLUGIN_OUTPUT or stderr_file.tell() > MAX_PLUGIN_OUTPUT:
            raise TargetError(422, "plugin_output_too_large")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(MAX_PLUGIN_OUTPUT + 1)
        stderr = stderr_file.read(MAX_PLUGIN_OUTPUT + 1)

    if return_code != 0:
        detail = stderr.decode("utf-8", "replace")[-512:]
        raise TargetError(422, "plugin_failed", detail)
    try:
        report = json.loads(stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetError(422, "plugin_report_invalid") from exc
    if not isinstance(report, dict):
        raise TargetError(422, "plugin_report_invalid")
    return {
        "argv": [sys.executable, "-I", str(plugin_path)],
        "http_pid": os.getpid(),
        "launcher_pid": process.pid,
        "launcher_uid": os.getuid(),
        "launcher_euid": os.geteuid(),
        "launcher_gid": os.getgid(),
        "launcher_egid": os.getegid(),
        "child_pid": process.pid,
        "returncode": return_code,
        "started_ns": started_ns,
        "duration_ms": duration_ms,
        "stderr": stderr.decode("utf-8", "replace"),
        "report": report,
    }


def read_keeper_result(proof_nonce: str, plugin_sha256: str) -> dict[str, Any]:
    path = RESULT_ROOT / f"{proof_nonce}.json"
    deadline = time.monotonic() + 2.0
    while True:
        try:
            body = path.read_bytes()
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise TargetError(409, "keeper_result_missing")
            time.sleep(0.02)
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != APP_GID
        or stat.S_IMODE(info.st_mode) != 0o640
    ):
        raise TargetError(409, "keeper_result_permissions_invalid")
    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        raise TargetError(409, "keeper_result_invalid") from exc
    if (
        not isinstance(result, dict)
        or result.get("ok") is not True
        or result.get("operation") != "write_proof"
        or result.get("proof_nonce") != proof_nonce
        or result.get("plugin_sha256") != plugin_sha256
    ):
        raise TargetError(409, "keeper_result_identity_invalid")
    return result


def verify_plugin_report(
    report: dict[str, Any],
    proof_nonce: str,
    plugin_sha256: str,
    keeper_result: dict[str, Any],
) -> None:
    required = {
        "plugin_pid",
        "plugin_uid",
        "plugin_euid",
        "plugin_gid",
        "plugin_egid",
        "proof_nonce",
        "plugin_sha256",
        "direct_write",
        "clean_control",
        "duplicate_attack",
    }
    if set(report) != required:
        raise TargetError(422, "plugin_report_fields_invalid")
    if (
        report["plugin_uid"] != APP_UID
        or report["plugin_euid"] != APP_UID
        or report["plugin_gid"] != APP_GID
        or report["plugin_egid"] != APP_GID
        or report["proof_nonce"] != proof_nonce
        or report["plugin_sha256"] != plugin_sha256
    ):
        raise TargetError(422, "plugin_identity_report_invalid")
    direct = report["direct_write"]
    if not isinstance(direct, dict) or direct.get("allowed") is not False or direct.get(
        "errno"
    ) not in (errno.EACCES, errno.EPERM):
        raise TargetError(422, "plugin_direct_write_control_invalid")
    clean = report["clean_control"]
    if not isinstance(clean, dict) or clean != {
        "error": "backend_role_denied",
        "ok": False,
    }:
        raise TargetError(422, "plugin_clean_control_invalid")
    duplicate = report["duplicate_attack"]
    if not isinstance(duplicate, dict) or duplicate.get("ok") is not True:
        raise TargetError(422, "plugin_duplicate_attack_invalid")
    for field in ("operation", "lab_id", "proof_nonce", "plugin_sha256"):
        if duplicate.get(field) != keeper_result.get(field):
            raise TargetError(422, "plugin_keeper_result_mismatch")
    peer = keeper_result.get("peer")
    if (
        not isinstance(peer, dict)
        or peer.get("uid") != APP_UID
        or peer.get("gid") != APP_GID
        or peer.get("pid") != report["plugin_pid"]
    ):
        raise TargetError(422, "keeper_peer_evidence_invalid")


def remove_plugin_as_app(expected_sha256: str) -> bool:
    path = PLUGIN_ROOT / PLUGIN_NAME
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise TargetError(409, "plugin_state_invalid")
    if sha256_bytes(path.read_bytes()) != expected_sha256:
        raise TargetError(409, "plugin_hash_mismatch")
    path.unlink()
    return True


def drop_to_application_identity() -> None:
    os.setgroups([])
    os.setgid(APP_GID)
    os.setuid(APP_UID)
    os.umask(0o077)
    if (
        os.getuid() != APP_UID
        or os.geteuid() != APP_UID
        or os.getgid() != APP_GID
        or os.getegid() != APP_GID
    ):
        raise RuntimeError("failed to drop application privileges")


def run_plugin_launcher(plugin_path_text: str) -> int:
    """Apply limits before exec without using preexec_fn in the HTTP process."""

    if os.getuid() != APP_UID or os.geteuid() != APP_UID:
        raise SystemExit("plugin launcher requires the application identity")
    if os.getgid() != APP_GID or os.getegid() != APP_GID:
        raise SystemExit("plugin launcher requires the application group")
    expected = str(PLUGIN_ROOT / PLUGIN_NAME)
    if plugin_path_text != expected or os.path.realpath(plugin_path_text) != expected:
        raise SystemExit("plugin launcher path denied")
    plugin_limits()
    environment = dict(os.environ)
    os.execve(
        sys.executable,
        [sys.executable, "-I", plugin_path_text],
        environment,
    )
    return 127


def run_http_child(config: Config, inherited_listener: socket.socket) -> int:
    inherited_listener.close()
    drop_to_application_identity()
    server = CrownfallHTTPServer((config.bind, config.port), config)

    def stop_server(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)
    print(
        json.dumps(
            {
                "time": utc_now(),
                "component": "http",
                "event": "ready",
                "bind": config.bind,
                "port": config.port,
                "pid": os.getpid(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "lab_id": config.lab_id,
                "target_fingerprint": config.target_fingerprint,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
    return 0


def create_keeper_listener() -> socket.socket:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(KEEPER_SOCKET))
    os.chown(KEEPER_SOCKET, 0, APP_GID)
    os.chmod(KEEPER_SOCKET, 0o660)
    listener.listen(16)
    return listener


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="run the disposable crownfall target", allow_abbrev=False
    )
    parser.add_argument("--lab-id", help="lab identifier; normally set by compose")
    parser.add_argument("--outer-key-hex", help="32-byte ownership key in lowercase hex")
    parser.add_argument("--bind", help="HTTP bind address inside the container")
    parser.add_argument("--port", type=int, help="HTTP port inside the container")
    parser.add_argument(
        "--clock-skew",
        type=int,
        default=30,
        help="maximum signed-request clock skew in seconds (default: 30)",
    )
    parser.add_argument("--plugin-launcher", metavar="PATH", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.plugin_launcher is not None:
        return run_plugin_launcher(args.plugin_launcher)
    ensure_root_runtime()
    config = Config.from_environment(args)
    # Keep the validated values available to the post-drop activation runner.
    os.environ["CROWNFALL_LAB_ID"] = config.lab_id
    os.environ["CROWNFALL_OUTER_KEY_HEX"] = config.outer_key.hex()
    prepare_layout()
    listener = create_keeper_listener()
    child_pid = os.fork()
    if child_pid == 0:
        try:
            return run_http_child(config, listener)
        except BaseException as exc:
            print(
                json.dumps(
                    {
                        "time": utc_now(),
                        "component": "http",
                        "event": "fatal",
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                    separators=(",", ":"),
                ),
                file=sys.stderr,
                flush=True,
            )
            return 1

    keeper = RootKeeper(config, listener)
    print(
        json.dumps(
            {
                "time": utc_now(),
                "component": "keeper",
                "event": "ready",
                "pid": os.getpid(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "child_pid": child_pid,
                "socket": str(KEEPER_SOCKET),
                "socket_mode": mode_text(KEEPER_SOCKET.stat().st_mode),
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    return keeper.serve(child_pid)


if __name__ == "__main__":
    raise SystemExit(main())
