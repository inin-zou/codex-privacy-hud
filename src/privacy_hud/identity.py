"""Exact, session-keyed identities and opaque labels for version-2
accounting (#54 Phase 3). Pure: no filesystem, environment or network.

Every identity is HMAC-SHA256 under the session key over a domain and its
fields, each framed as an eight-byte big-endian length followed by its UTF-8
bytes. The framing, not a delimiter, keeps fields from running into each
other; the domain keeps a value, a file and a recipient with the same text
apart. Nothing here normalizes case or whitespace: two strings are the same
subject only when they are the same string.
"""
from __future__ import annotations

import hashlib
import hmac
import posixpath
import re
import unicodedata
from typing import get_args

from .accounting import DataType, DestinationKind, SafeSuffix

_VALUE_DOMAIN = "privacy-hud/54/value/v1"
_FILE_DOMAIN = "privacy-hud/54/file/v1"
_RECIPIENT_DOMAIN = "privacy-hud/54/recipient/v1"

_INVALID_IDENTITY = "invalid accounting identity"
_INVALID_OBSERVATION = "invalid accounting observation"

_DATA_TYPES: tuple[str, ...] = get_args(DataType)
_DESTINATIONS: tuple[str, ...] = get_args(DestinationKind)
_SAFE_SUFFIXES: tuple[str, ...] = get_args(SafeSuffix)

#: Opaque ledger-generated subject and recipient IDs.
_OPAQUE_ID = re.compile(r"[0-9a-f]{32}")

#: Text a shell would still have expanded: a path containing one of these
#: was not evaluated, and hashing it would invent a file identity.
_UNEVALUATED = re.compile(r"[$`*?]|^~")

_DOT = "•"


def _encode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise ValueError(_INVALID_IDENTITY)
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(_INVALID_IDENTITY) from None
    return len(raw).to_bytes(8, "big") + raw


def _identity(key: bytes, domain: str, *fields: str) -> bytes:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError(_INVALID_IDENTITY)
    message = _encode(domain) + b"".join(_encode(f) for f in fields)
    return hmac.new(key, message, hashlib.sha256).digest()


def value_identity(key: bytes, value: str) -> bytes:
    """The exact value, byte for byte: no case folding, no trimming."""
    return _identity(key, _VALUE_DOMAIN, value)


def _checked_path(path: object) -> str:
    if (not isinstance(path, str) or not path or "\x00" in path
            or _UNEVALUATED.search(path)):
        raise ValueError(_INVALID_IDENTITY)
    return path


def file_identity(
    key: bytes, evaluated_path: str, cwd: str,
) -> bytes:
    """The evaluated path, made absolute against the supplied `cwd` and
    normalized lexically. Never the process's own working directory, the
    home directory, the environment or the filesystem: no symlink is
    followed and nothing is read. An input that cannot be resolved this way
    raises; the caller then records an unresolved subject instead."""
    path = _checked_path(evaluated_path)
    if not path.startswith("/"):
        base = _checked_path(cwd)
        if not base.startswith("/"):
            raise ValueError(_INVALID_IDENTITY)
        path = posixpath.join(base, path)
    return _identity(key, _FILE_DOMAIN, posixpath.normpath(path))


def recipient_identity(
    key: bytes,
    destination_kind: DestinationKind,
    concrete_identity: str,
) -> bytes:
    if destination_kind not in _DESTINATIONS:
        raise ValueError(_INVALID_IDENTITY)
    return _identity(key, _RECIPIENT_DOMAIN, destination_kind,
                     concrete_identity)


def safe_file_label(
    subject_id: str, evaluated_path: str,
) -> str:
    """`file {subject_id}`, plus the extension when it is one of the four
    key-container suffixes. No directory, basename or other extension."""
    if not isinstance(subject_id, str) or not _OPAQUE_ID.fullmatch(subject_id):
        raise ValueError(_INVALID_IDENTITY)
    if (not isinstance(evaluated_path, str) or not evaluated_path
            or "\x00" in evaluated_path):
        raise ValueError(_INVALID_IDENTITY)
    suffix = posixpath.splitext(posixpath.basename(evaluated_path))[1].lower()
    if suffix in _SAFE_SUFFIXES:
        return f"file {subject_id} ({suffix})"
    return f"file {subject_id}"


def safe_masked_example(
    data_type: DataType, value: str,
) -> str | None:
    """A masked exemplar, or None when nothing may be shown.

    Credentials and paths get none. Short values are a fixed four dots, so
    the mask is not a length oracle. Longer values keep their first two and
    last character. Unlike the legacy mask there is no email special case:
    the domain is not kept."""
    if data_type not in _DATA_TYPES or not isinstance(value, str):
        raise ValueError(_INVALID_OBSERVATION)
    if data_type in ("credential", "path"):
        return None
    if len(value) <= 4:
        retained = ""
        masked = _DOT * 4
    else:
        retained = value[:2] + value[-1]
        masked = f"{value[:2]}{_DOT * 3}{value[-1]}"
    if value in masked:
        return None
    if any(unicodedata.category(c) == "Cc" for c in retained):
        return None
    return masked
