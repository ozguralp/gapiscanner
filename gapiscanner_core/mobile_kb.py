"""Shared normalization helpers for multi-app mobile KB state."""

from __future__ import annotations

import re
from typing import Iterable, List, Mapping, Optional, Tuple


def _valid_label(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if value.startswith("mobile:ios:"):
        return bool(re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", value.split("mobile:ios:", 1)[1]))
    if value.startswith("mobile:android:"):
        rest = value.split("mobile:android:", 1)[1]
        if ":" not in rest:
            return False
        package, sha1 = rest.split(":", 1)
        return bool(re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package)
                    and re.fullmatch(r"[A-Fa-f0-9]{40}", sha1.replace(":", "")))
    return False


def merge_mobile_restrictions(
    existing: Optional[Iterable[object]],
    new_value: Optional[object] = None,
) -> List[str]:
    """Return every valid distinct mobile restriction in stable order."""
    values: List[object]
    if isinstance(existing, str):
        values = [existing]
    else:
        values = list(existing) if isinstance(existing, (list, tuple, set)) else []
    if isinstance(new_value, (list, tuple, set)):
        values.extend(new_value)
    elif new_value is not None:
        values.append(new_value)
    return sorted({value for value in values if _valid_label(value)})


def mobile_restriction_contexts(
    labels: Optional[Iterable[object]],
) -> List[Tuple[str, str, str]]:
    """Convert persisted labels to all replayable (mode, value, label) rows."""
    contexts: List[Tuple[str, str, str]] = []
    for label in merge_mobile_restrictions(labels):
        if label.startswith("mobile:ios:"):
            contexts.append(("ios", label.split("mobile:ios:", 1)[1], label))
        else:
            rest = label.split("mobile:android:", 1)[1]
            contexts.append(("android", rest, label))
    return contexts


def mobile_restrictions_from_kb_entry(
    entry: Mapping[str, object],
) -> List[str]:
    """Return current and legacy mobile restriction labels for a KB row.

    Older KB records persisted ``mobile:android:...`` / ``mobile:ios:...``
    labels only as ``sources[*].url`` (or occasionally as a bare string).
    Re-scan callers must replay those contexts too; otherwise an old
    Android-restricted key is tested only without its package/certificate
    headers and can be misclassified as invalid or rotated.
    """
    if not isinstance(entry, Mapping):
        return []

    labels: List[object] = []
    labels.extend(merge_mobile_restrictions(entry.get("mobile_restrictions")))
    if entry.get("mobile_restriction"):
        labels.append(entry.get("mobile_restriction"))

    sources = entry.get("sources") or []
    if isinstance(sources, (str, Mapping)):
        sources = [sources]
    for source in sources if isinstance(sources, (list, tuple, set)) else ():
        if isinstance(source, Mapping):
            labels.append(source.get("url"))
        else:
            labels.append(source)
    return merge_mobile_restrictions(labels)


def known_project_from_history(entry: Mapping[str, object]) -> Optional[str]:
    """Return the newest persisted project ID, falling back to project number."""
    history = entry.get("scan_history") if isinstance(entry, Mapping) else None
    if not isinstance(history, list):
        return None
    for record in reversed(history):
        if not isinstance(record, Mapping):
            continue
        project_id = record.get("project_id")
        if project_id:
            return str(project_id)
        project_number = record.get("project_number")
        if project_number:
            return str(project_number)
    return None
