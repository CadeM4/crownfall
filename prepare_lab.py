#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import stat
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path


SERVICE_NAME = "crownfall-disposable-target"
PROTOCOL_VERSION = 1
FINGERPRINT_LABEL = b"crownfall-target-v1\x00"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "prepared"


class PreparationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetUrl:
    rendered: str
    scheme: str
    host: str
    port: int


@dataclass(frozen=True)
class Authorization:
    service: str
    protocol: int
    base_url: str
    lab_id: str
    outer_key_hex: str
    target_fingerprint: str


def parse_target_url(value: str) -> TargetUrl:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PreparationError(f"invalid base URL: {exc}") from exc

    if parsed.scheme not in {"http", "https"}:
        raise PreparationError("base URL scheme must be http or https")
    if not parsed.hostname:
        raise PreparationError("base URL has no hostname")
    if parsed.username is not None or parsed.password is not None:
        raise PreparationError("credentials do not belong in the base URL")
    if parsed.query or parsed.fragment:
        raise PreparationError("base URL cannot contain a query or fragment")
    if parsed.path not in {"", "/"}:
        raise PreparationError("base URL cannot contain a path")

    host = parsed.hostname.rstrip(".").lower()
    if not host:
        raise PreparationError("base URL hostname is empty")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in host):
        raise PreparationError("base URL hostname must be printable ASCII")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if parsed.scheme == "http" and address is not None:
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise PreparationError("plain HTTP is restricted to private or loopback addresses")

    default_port = 443 if parsed.scheme == "https" else 80
    rendered_host = f"[{host}]" if ":" in host else host
    suffix = "" if port == default_port else f":{port}"
    return TargetUrl(f"{parsed.scheme}://{rendered_host}{suffix}", parsed.scheme, host, port)


def parse_bind_address(value: str, expose_all: bool) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise PreparationError("bind address must be an IPv4 literal") from exc
    if address.is_multicast or address.is_reserved:
        raise PreparationError("bind address cannot be multicast or reserved")
    if address.is_unspecified and not expose_all:
        raise PreparationError("0.0.0.0 requires --expose-all-interfaces")
    return str(address)


def target_fingerprint(lab_id: str, key: bytes) -> str:
    return hmac.new(key, FINGERPRINT_LABEL + lab_id.encode("ascii"), hashlib.sha256).hexdigest()


def ensure_new_directory(path: Path) -> Path:
    expanded = path.expanduser()
    resolved_parent = expanded.parent.resolve()
    resolved = resolved_parent / expanded.name
    if resolved.exists() or resolved.is_symlink():
        raise PreparationError(f"output already exists: {resolved}")
    resolved.mkdir(mode=0o700)
    return resolved


def write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PreparationError(f"short write while creating {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def prepare(
    base_url: TargetUrl,
    output: Path,
    bind_address: str,
    listen_port: int,
) -> dict[str, object]:
    if not 1 <= listen_port <= 65535:
        raise PreparationError("listen port must be between 1 and 65535")

    destination = ensure_new_directory(output)
    lab_id = secrets.token_hex(16)
    outer_key = secrets.token_bytes(32)
    fingerprint = target_fingerprint(lab_id, outer_key)
    authorization = Authorization(
        service=SERVICE_NAME,
        protocol=PROTOCOL_VERSION,
        base_url=base_url.rendered,
        lab_id=lab_id,
        outer_key_hex=outer_key.hex(),
        target_fingerprint=fingerprint,
    )

    target_env = "\n".join(
        (
            f"CROWNFALL_LAB_ID={lab_id}",
            f"CROWNFALL_OUTER_KEY_HEX={outer_key.hex()}",
            f"CROWNFALL_BIND={bind_address}",
            f"CROWNFALL_PORT={listen_port}",
            "",
        )
    ).encode("ascii")
    authorization_json = (
        json.dumps(asdict(authorization), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    deployment_json = (
        json.dumps(
            {
                "service": SERVICE_NAME,
                "protocol": PROTOCOL_VERSION,
                "bind_address": bind_address,
                "listen_port": listen_port,
                "base_url": base_url.rendered,
                "lab_id": lab_id,
                "target_fingerprint": fingerprint,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    try:
        write_private(destination / "target.env", target_env)
        write_private(destination / "authorization.json", authorization_json)
        write_private(destination / "deployment.json", deployment_json)
    except BaseException:
        for name in ("target.env", "authorization.json", "deployment.json"):
            try:
                (destination / name).unlink()
            except OSError:
                pass
        try:
            destination.rmdir()
        except OSError:
            pass
        raise

    return {
        "output_directory": str(destination),
        "target_environment": str(destination / "target.env"),
        "authorization": str(destination / "authorization.json"),
        "deployment": str(destination / "deployment.json"),
        "base_url": base_url.rendered,
        "lab_id": lab_id,
        "target_fingerprint": fingerprint,
    }


def bounded_port(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="prepare one disposable crownfall target and its locked authorization file",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--i-own-this-lab",
        action="store_true",
        help="required acknowledgement for preparing the target",
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="final URL of the disposable target, used to lock the attack client",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"new directory for generated material (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--bind-address",
        default="127.0.0.1",
        help="host address published by the deployment (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--listen-port",
        type=bounded_port,
        default=8080,
        help="target HTTP port (default: 8080)",
    )
    parser.add_argument(
        "--expose-all-interfaces",
        action="store_true",
        help="permit 0.0.0.0 as the deployment bind address",
    )
    args = parser.parse_args(argv)
    if not args.i_own_this_lab:
        parser.error("refusing to prepare a target without --i-own-this-lab")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = prepare(
            parse_target_url(args.base_url),
            args.output,
            parse_bind_address(args.bind_address, args.expose_all_interfaces),
            args.listen_port,
        )
    except (PreparationError, OSError) as exc:
        print(f"prepare_lab: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
