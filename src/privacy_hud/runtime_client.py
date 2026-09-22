# src/privacy_hud/runtime_client.py
"""The client half of socket protocol 2 (#66). Stdlib only.

One connection carries exactly one exchange:

    -> hello {"v":2,"op":"hello","build_id":…,"activation_epoch":…,
              "storage_generation":1}
    <- hello {"v":2,"op":"hello","ok":true,"release":…,"build_id":…,
              "activation_epoch":…,"storage_generation":1,
              "schema_version":…,"ready":true}
    -> one request, in the same identity envelope
    <- its reply, {"v":2,"op":<same op>,"ok":true,…}

Nothing but the hello is sent until a hello naming the selected build and
epoch has come back on this connection. One absolute monotonic deadline,
taken before `connect()`, bounds the connect, the hello, the request and
its reply together. Frames are newline-delimited JSON, bounded at 16 KiB
for the hello and 8 MiB for anything else.

A request is never replayed: once it has been sent, a timeout or a lost
reply is an unknown outcome, and this module reports it as a failure
without retrying. `hooks/handler.py` restates this protocol, since it may
not import the package; `tests/test_runtime_protocol.py` pins the two.

I1: failures carry a fixed `FailureCode`, never peer bytes.
"""
from __future__ import annotations

import json
import socket
import time
from pathlib import Path

from . import codex
from .runtime_contract import (
    PROTOCOL_VERSION,
    STORAGE_GENERATION,
    Activation,
    JSONObject,
    RuntimeRefusal,
    is_int,
)

HELLO_FRAME_LIMIT = 16 * 1024
EVENT_FRAME_LIMIT = 8 * 1024 * 1024

OP_HELLO = "hello"
OP_EVENT = "event"
OP_ACTIVE_SESSIONS = "active_sessions"
OP_POLICY_UPDATE = "policy_update"
REQUEST_OPS = frozenset({OP_EVENT, OP_ACTIVE_SESSIONS, OP_POLICY_UPDATE})

HELLO_FIELDS = frozenset({"v", "op", "build_id", "activation_epoch",
                          "storage_generation"})
HELLO_REPLY_FIELDS = frozenset({"v", "op", "ok", "release", "build_id",
                                "activation_epoch", "storage_generation",
                                "schema_version", "ready"})
ENVELOPE_FIELDS = frozenset({"v", "op", "build_id", "activation_epoch"})


class FrameError(Exception):
    """A frame was oversized, truncated, or not a JSON object."""


def encode_frame(message: JSONObject) -> bytes:
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


def decode_frame(line: bytes) -> JSONObject:
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FrameError() from None
    if not isinstance(value, dict):
        raise FrameError()
    return value


def hello_request(activation: Activation) -> JSONObject:
    return {"v": PROTOCOL_VERSION, "op": OP_HELLO,
            "build_id": activation.identity.build_id,
            "activation_epoch": activation.epoch,
            "storage_generation": STORAGE_GENERATION}


def hello_reply(activation: Activation, schema_version: int) -> JSONObject:
    return {"v": PROTOCOL_VERSION, "op": OP_HELLO, "ok": True,
            "release": activation.identity.release,
            "build_id": activation.identity.build_id,
            "activation_epoch": activation.epoch,
            "storage_generation": STORAGE_GENERATION,
            "schema_version": schema_version, "ready": True}


def is_valid_hello(message: object) -> bool:
    """Structurally a protocol-2 hello: exact fields, integer (not boolean)
    versions. Identity is compared separately."""
    return (isinstance(message, dict) and set(message) == HELLO_FIELDS
            and is_int(message["v"]) and message["v"] == PROTOCOL_VERSION
            and message["op"] == OP_HELLO
            and isinstance(message["build_id"], str)
            and isinstance(message["activation_epoch"], str)
            and is_int(message["storage_generation"])
            and message["storage_generation"] == STORAGE_GENERATION)


def hello_matches(message: JSONObject, activation: Activation) -> bool:
    return (message["build_id"] == activation.identity.build_id
            and message["activation_epoch"] == activation.epoch)


def is_matching_hello_reply(message: object,
                            activation: Activation) -> bool:
    return (isinstance(message, dict)
            and set(message) == HELLO_REPLY_FIELDS
            and is_int(message["v"]) and message["v"] == PROTOCOL_VERSION
            and message["op"] == OP_HELLO and message["ok"] is True
            and isinstance(message["release"], str)
            and message["build_id"] == activation.identity.build_id
            and message["activation_epoch"] == activation.epoch
            and is_int(message["storage_generation"])
            and message["storage_generation"] == STORAGE_GENERATION
            and is_int(message["schema_version"])
            and message["schema_version"]
            in activation.identity.readable_schemas
            and message["ready"] is True)


def is_request_envelope(message: object, activation: Activation) -> bool:
    """A protocol-2 request after hello: known op, this build and epoch."""
    return (isinstance(message, dict)
            and ENVELOPE_FIELDS <= set(message)
            and is_int(message["v"]) and message["v"] == PROTOCOL_VERSION
            and message["op"] in REQUEST_OPS
            and message["build_id"] == activation.identity.build_id
            and message["activation_epoch"] == activation.epoch)


def is_ok_reply(message: object, op: str) -> bool:
    return (isinstance(message, dict)
            and is_int(message.get("v")) and message.get("v") == PROTOCOL_VERSION
            and message.get("op") == op and message.get("ok") is True)


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError()
    return left


def read_frame(sock: socket.socket, limit: int, deadline: float) -> bytes:
    """One newline-terminated frame of at most `limit` bytes (newline
    excluded), before `deadline`. Nothing may follow it on this connection.
    """
    buf = b""
    while b"\n" not in buf:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(min(65536, limit + 2 - len(buf)))
        if not chunk:
            raise FrameError()
        buf += chunk
        if len(buf) > limit + 1 and b"\n" not in buf:
            raise FrameError()
    line, rest = buf.split(b"\n", 1)
    if len(line) > limit or rest:
        raise FrameError()
    return line


def send_frame(sock: socket.socket, data: bytes, deadline: float) -> None:
    sock.settimeout(_remaining(deadline))
    sock.sendall(data)


class RuntimeConnection:
    """A connection on which a matching hello has completed. Carries one
    request; after that, or after any failure, it is closed."""

    def __init__(self, sock: socket.socket, activation: Activation,
                 deadline: float, hello: JSONObject) -> None:
        self._sock: socket.socket | None = sock
        self._activation = activation
        self._deadline = deadline
        self.hello = hello

    def request(self, op: str, body: JSONObject) -> JSONObject:
        """Send one request in the identity envelope and return its
        validated reply. Raises `RuntimeRefusal("request_failed")` on any
        failure, including after the request was sent: then the outcome is
        unknown, and it is never retried."""
        if op not in REQUEST_OPS or ENVELOPE_FIELDS & set(body):
            raise ValueError("not a protocol-2 request")
        sock, self._sock = self._sock, None
        if sock is None:
            raise RuntimeRefusal("request_failed")
        try:
            message: JSONObject = {
                "v": PROTOCOL_VERSION, "op": op,
                "build_id": self._activation.identity.build_id,
                "activation_epoch": self._activation.epoch, **body}
            data = encode_frame(message)
            if len(data) > EVENT_FRAME_LIMIT + 1:
                raise FrameError()
            send_frame(sock, data, self._deadline)
            reply = decode_frame(read_frame(sock, EVENT_FRAME_LIMIT,
                                            self._deadline))
        except (OSError, FrameError, ValueError):
            raise RuntimeRefusal("request_failed") from None
        finally:
            _close(sock)
        if not is_ok_reply(reply, op):
            raise RuntimeRefusal("request_failed")
        return reply

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            _close(sock)

    def __enter__(self) -> "RuntimeConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def connect_socket(socket_path: Path, *, activation: Activation,
                   timeout: float) -> RuntimeConnection:
    """`connect_runtime` against an explicit socket path.

    Raises `RuntimeRefusal`: `request_failed` when nothing answered in time
    or the transport failed, `runtime_mismatch` when something answered but
    not with a hello from the selected build and epoch (an older daemon, a
    daemon of another build, or anything else holding the socket).
    """
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect(str(socket_path))
        send_frame(sock, encode_frame(hello_request(activation)), deadline)
        line = read_frame(sock, HELLO_FRAME_LIMIT, deadline)
    except TimeoutError:
        _close(sock)
        raise RuntimeRefusal("request_failed") from None
    except FrameError:
        _close(sock)
        raise RuntimeRefusal("runtime_mismatch") from None
    except OSError:
        _close(sock)
        raise RuntimeRefusal("request_failed") from None
    try:
        reply = decode_frame(line)
    except FrameError:
        _close(sock)
        raise RuntimeRefusal("runtime_mismatch") from None
    if not is_matching_hello_reply(reply, activation):
        _close(sock)
        raise RuntimeRefusal("runtime_mismatch")
    return RuntimeConnection(sock, activation, deadline, reply)


def connect_runtime(
    data_dir: Path, *, activation: Activation, timeout: float
) -> RuntimeConnection:
    """Connect to `$PLUGIN_DATA/daemon.sock` and complete the hello."""
    return connect_socket(codex.socket_path(Path(data_dir)),
                          activation=activation, timeout=timeout)
