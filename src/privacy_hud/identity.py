"""Exact, session-keyed identities and opaque labels for version-2
accounting (#54 Phase 3). Pure: no filesystem, environment or network."""
from __future__ import annotations

from .accounting import DataType, DestinationKind, _scaffold


def value_identity(key: bytes, value: str) -> bytes:
    _scaffold()


def file_identity(
    key: bytes, evaluated_path: str, cwd: str,
) -> bytes:
    _scaffold()


def recipient_identity(
    key: bytes,
    destination_kind: DestinationKind,
    concrete_identity: str,
) -> bytes:
    _scaffold()


def safe_file_label(
    subject_id: str, evaluated_path: str,
) -> str:
    _scaffold()


def safe_masked_example(
    data_type: DataType, value: str,
) -> str | None:
    _scaffold()
