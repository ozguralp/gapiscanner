"""Deterministic URL scheduling and resumable crawl-fetch state."""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, urlunparse


BINARY_EXTENSIONS: Tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm",
    ".mp3", ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar",
)

_SCRIPT_EXTENSIONS = (".js", ".mjs", ".cjs", ".map")
_STRUCTURED_EXTENSIONS = (".json", ".webmanifest", ".xml")
_TEXT_EXTENSIONS = (".html", ".htm", ".css", ".txt", ".php", ".jsp", ".aspx")


@dataclass(frozen=True)
class URLFetchPlan:
    """One deterministic fetch slice and the auditable remainder."""

    selected: Tuple[str, ...]
    pending: Tuple[str, ...]
    skipped_binary: Tuple[str, ...]
    completed: Tuple[str, ...]
    candidate_count: int
    budget: Optional[int]


def _canonical_url(raw_url: object) -> Optional[str]:
    if not isinstance(raw_url, str):
        return None
    value = raw_url.strip()
    if not value.startswith(("http://", "https://")):
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if not parsed.netloc:
        return None
    try:
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
    except ValueError:
        return None
    if not host:
        return None
    if ":" in host:
        host = "[" + host + "]"
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    netloc = host if port is None or default_port else "%s:%d" % (host, port)
    return urlunparse((
        parsed.scheme.lower(), netloc, parsed.path or "/", parsed.params,
        parsed.query, "",
    ))


def _is_binary(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(BINARY_EXTENSIONS)


def _same_site_rank(url: str, seed_url: Optional[str]) -> int:
    if not seed_url:
        return 0
    try:
        host = (urlparse(url).hostname or "").lower()
        seed_host = (urlparse(seed_url).hostname or "").lower()
    except ValueError:
        return 2
    if host == seed_host:
        return 0
    if host.endswith("." + seed_host) or seed_host.endswith("." + host):
        return 1
    return 2


def _priority(url: str, seed_url: Optional[str]) -> tuple:
    path = urlparse(url).path.lower()
    if path.endswith(_SCRIPT_EXTENSIONS):
        kind = 0
    elif path.endswith(_STRUCTURED_EXTENSIONS):
        kind = 1
    elif path.endswith(_TEXT_EXTENSIONS) or "." not in path.rsplit("/", 1)[-1]:
        kind = 2
    else:
        kind = 3
    return (kind, _same_site_rank(url, seed_url), url)


def build_url_fetch_plan(
    urls: Iterable[object],
    *,
    seed_url: Optional[str] = None,
    budget: Optional[int] = None,
    completed_urls: Optional[Iterable[object]] = None,
) -> URLFetchPlan:
    """Return a stable URL order and optional bounded slice.

    ``budget=None`` or ``budget=0`` means fetch every text candidate.  A
    positive budget is explicit operator intent; unselected candidates are
    returned in ``pending`` and must never disappear silently.
    """
    if budget is not None and budget < 0:
        raise ValueError("URL fetch budget must be >= 0")
    canonical = {_canonical_url(url) for url in urls}
    canonical.discard(None)
    skipped_binary = tuple(sorted(url for url in canonical if _is_binary(url)))
    candidates = {url for url in canonical if not _is_binary(url)}
    completed = {_canonical_url(url) for url in (completed_urls or ())}
    completed.discard(None)
    completed_in_plan = tuple(sorted(candidates & completed))
    remaining = sorted(candidates - completed, key=lambda u: _priority(u, seed_url))
    effective_budget = None if budget in (None, 0) else int(budget)
    if effective_budget is None:
        selected = tuple(remaining)
        pending: Sequence[str] = ()
    else:
        selected = tuple(remaining[:effective_budget])
        pending = tuple(remaining[effective_budget:])
    return URLFetchPlan(
        selected=selected,
        pending=tuple(pending),
        skipped_binary=skipped_binary,
        completed=completed_in_plan,
        candidate_count=len(candidates),
        budget=effective_budget,
    )


def load_completed_manifest_urls(path: object) -> Set[str]:
    """Load successfully fetched URLs from the scanner response manifest."""
    manifest = Path(path)
    if not manifest.is_file():
        return set()
    completed: Set[str] = set()
    try:
        with manifest.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                status = str(row.get("status") or "")
                if not status or status.startswith("ERR:"):
                    continue
                url = _canonical_url(row.get("url"))
                if url:
                    completed.add(url)
    except (OSError, csv.Error, UnicodeError):
        return set()
    return completed


def load_url_queue_completed_urls(path: object) -> Set[str]:
    """Load the completed subset from a prior queue-state file."""
    target = Path(path)
    if not target.is_file():
        return set()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return set()
    completed: Set[str] = set()
    rows = payload.get("completed") if isinstance(payload, dict) else None
    for raw_url in rows if isinstance(rows, list) else ():
        url = _canonical_url(raw_url)
        if url:
            completed.add(url)
    return completed


def write_url_queue_state(
    path: object,
    plan: URLFetchPlan,
    *,
    seed_url: Optional[str] = None,
) -> str:
    """Atomically persist the selected/pending queue without response data."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(plan)
    payload["schema_version"] = 1
    payload["seed_url"] = seed_url
    payload["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    temp = target.with_name(target.name + ".tmp-%d" % os.getpid())
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp, target)
    return str(target)
