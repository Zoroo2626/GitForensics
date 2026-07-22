"""Shared limits and sanitizers for hostile repository data."""

from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from heapq import nsmallest
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"
TRUNCATED = "...[TRUNCATED]"

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069\ufeff]")
_EMAIL_RE = re.compile(r"(?<![\w.+\-\[])([\w.+-])[\w.+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_SECRET_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})\b"),
    re.compile(
        r"(?i)(\b(?:authorization|bearer|token|password|passwd|secret|api[_-]?key)\b\s*[:=]?\s*)([^\s,;]+)"
    ),
    re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}"),
)


def _safe_string(value: Any) -> str:
    """Convert hostile library values without trusting custom string methods."""
    try:
        return str(value)
    except Exception:
        return f"<{type(value).__name__}>"


@dataclass(frozen=True)
class SecurityLimits:
    """Configurable resource ceilings with practical defaults for normal repositories."""

    max_commits: int = 50_000
    max_tags: int = 10_000
    max_refs: int = 20_000
    max_git_stdout_bytes: int = 64 * 1024 * 1024
    max_git_stderr_bytes: int = 1 * 1024 * 1024
    max_workflow_file_bytes: int = 500_000
    max_workflow_files: int = 100
    max_api_response_bytes: int = 8 * 1024 * 1024
    max_api_pages: int = 20
    max_releases: int = 2_000
    max_release_assets: int = 5_000
    max_attestation_payload_bytes: int = 1 * 1024 * 1024
    max_evidence_string_chars: int = 512
    max_evidence_items: int = 50
    max_findings: int = 2_000
    max_metadata_chars: int = 16_384
    max_diff_entries: int = 1_000_000

    def validate(self) -> None:
        """Reject nonsensical or effectively unbounded configurations."""
        values = self.__dict__
        for name, value in values.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer.")
        if self.max_commits > 10_000_000:
            raise ValueError("max_commits cannot exceed 10,000,000.")
        if self.max_git_stdout_bytes > 1024**3 or self.max_api_response_bytes > 256 * 1024**2:
            raise ValueError("Configured output limit is unsafe.")
        safe_caps = {
            "max_tags": 1_000_000,
            "max_refs": 1_000_000,
            "max_git_stderr_bytes": 64 * 1024**2,
            "max_workflow_file_bytes": 64 * 1024**2,
            "max_workflow_files": 10_000,
            "max_api_pages": 1_000,
            "max_releases": 100_000,
            "max_release_assets": 1_000_000,
            "max_attestation_payload_bytes": 64 * 1024**2,
            "max_evidence_string_chars": 1_000_000,
            "max_evidence_items": 10_000,
            "max_findings": 100_000,
            "max_metadata_chars": 16 * 1024**2,
            "max_diff_entries": 100_000_000,
        }
        for name, maximum in safe_caps.items():
            if values[name] > maximum:
                raise ValueError(f"{name} cannot exceed {maximum:,}.")


def _redact_url(value: str) -> str:
    """Remove URL credentials and query/fragment values without changing normal paths."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def sanitize_text(
    value: str,
    *,
    max_chars: int = 16_384,
    secrets: tuple[str | None, ...] = (),
    minimize_emails: bool = True,
) -> str:
    """Redact credentials, terminal controls, bidi controls, and excessive text."""
    text = _safe_string(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    text = _redact_url(text)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_RE.sub("\ufffd", text)
    text = _BIDI_RE.sub("", text)
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            text = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)
    if minimize_emails:
        text = _EMAIL_RE.sub(lambda match: f"{match.group(1)}***@{match.group(2)}", text)
    if len(text) > max_chars:
        keep = max(0, max_chars - len(TRUNCATED))
        text = text[:keep] + TRUNCATED
    return text


def sanitize_path(value: str) -> str:
    """Normalize display paths and remove temporary/home-directory disclosure."""
    cleaned = sanitize_text(value, minimize_emails=False).replace("\\", "/")
    cleaned = re.sub(
        r"(?i)(?:[A-Z]:)?/[^\s]*/(?:gitforensics_(?:clone|git_home)_[A-Za-z0-9_-]+)(?:/)?",
        "<TEMP>/",
        cleaned,
    )
    try:
        home = str(Path.home()).replace("\\", "/").rstrip("/")
        if home and cleaned.lower().startswith(home.lower() + "/"):
            cleaned = "<HOME>/" + cleaned[len(home) + 1 :]
    except RuntimeError:
        pass
    return cleaned


def sanitize_value(
    value: Any,
    *,
    limits: SecurityLimits | None = None,
    secrets: tuple[str | None, ...] = (),
    _depth: int = 0,
    _active_ids: set[int] | None = None,
) -> Any:
    """Recursively make untrusted values bounded, deterministic, and JSON-safe."""
    cfg = limits or SecurityLimits()
    if _depth >= 6:
        return TRUNCATED
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return sanitize_text(
            value,
            max_chars=cfg.max_evidence_string_chars,
            secrets=secrets,
        )
    active_ids = _active_ids if _active_ids is not None else set()
    is_container = isinstance(value, (Mapping, Sequence, Set)) and not isinstance(
        value, (str, bytes, bytearray)
    )
    value_id = id(value)
    if is_container and value_id in active_ids:
        return "[CYCLE]"
    if is_container:
        active_ids.add(value_id)

    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        try:
            items = nsmallest(
                cfg.max_evidence_items,
                value.items(),
                key=lambda item: _safe_string(item[0]),
            )
            for key, item in items:
                safe_key = sanitize_text(_safe_string(key), max_chars=128, secrets=secrets)
                output[safe_key] = sanitize_value(
                    item,
                    limits=cfg,
                    secrets=secrets,
                    _depth=_depth + 1,
                    _active_ids=active_ids,
                )
            if len(value) > cfg.max_evidence_items:
                output["_truncated_items"] = len(value) - cfg.max_evidence_items
            return output
        finally:
            active_ids.discard(value_id)
    if isinstance(value, (list, tuple)):
        try:
            result = [
                sanitize_value(
                    item,
                    limits=cfg,
                    secrets=secrets,
                    _depth=_depth + 1,
                    _active_ids=active_ids,
                )
                for item in value[: cfg.max_evidence_items]
            ]
            if len(value) > cfg.max_evidence_items:
                result.append(f"{TRUNCATED} {len(value) - cfg.max_evidence_items} item(s)")
            return result
        finally:
            active_ids.discard(value_id)
    if isinstance(value, (set, frozenset)):
        try:
            sequence = nsmallest(cfg.max_evidence_items, value, key=_safe_string)
            result = [
                sanitize_value(
                    item,
                    limits=cfg,
                    secrets=secrets,
                    _depth=_depth + 1,
                    _active_ids=active_ids,
                )
                for item in sequence
            ]
            if len(value) > cfg.max_evidence_items:
                result.append(f"{TRUNCATED} {len(value) - cfg.max_evidence_items} item(s)")
            return result
        finally:
            active_ids.discard(value_id)
    if is_container:
        active_ids.discard(value_id)
    try:
        representation = repr(value)
    except Exception:
        representation = f"<{type(value).__name__}>"
    return sanitize_text(
        representation,
        max_chars=cfg.max_evidence_string_chars,
        secrets=secrets,
    )


def safe_output_path(output_path: str) -> Path:
    """Resolve an output location without following an existing final symlink."""
    raw = Path(output_path).expanduser()
    absolute = Path(os.path.abspath(str(raw)))
    for component in (absolute, *absolute.parents):
        if component == Path(component.anchor):
            continue
        if component.exists() and component.is_symlink():
            raise ValueError("Refusing to write through a symbolic-link output path.")
    return absolute
