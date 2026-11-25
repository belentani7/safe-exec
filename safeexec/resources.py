"""Locate policy resources both in a source checkout and in a wheel install.

``importlib.resources`` is the only reliable way to read data files from a
wheel: ``Path(__file__).parents[1]`` points inside ``site-packages`` and the
file simply is not there. This module centralises that lookup so the CLI, the
service and the tools all agree.
"""

from __future__ import annotations

from contextlib import ExitStack
from importlib import resources
from pathlib import Path

RULES_RESOURCE = "rules.yaml"

# ``resources.as_file`` yields a temporary path for zip-imported packages. We
# keep the context open for the process lifetime so callers may use the path
# without holding a context manager.
_EXIT_STACK = ExitStack()
_CACHE: dict[str, Path] = {}


def packaged_rules_path() -> Path:
    """Return a filesystem path to the packaged ``rules.yaml``."""
    cached = _CACHE.get(RULES_RESOURCE)
    if cached is not None and cached.is_file():
        return cached

    resource = resources.files("safeexec").joinpath(RULES_RESOURCE)
    if not resource.is_file():
        raise FileNotFoundError(
            f"packaged policy {RULES_RESOURCE!r} is missing; reinstall safe-exec-protocol"
        )

    # Installs from a directory or a wheel expose a real path; use it directly.
    try:
        direct = Path(str(resource))
    except (TypeError, ValueError):
        direct = None
    if direct is not None and direct.is_file():
        _CACHE[RULES_RESOURCE] = direct
        return direct

    # Zip import: materialise once and keep it alive.
    path = _EXIT_STACK.enter_context(resources.as_file(resource))
    _CACHE[RULES_RESOURCE] = path
    return path


def read_rules_text() -> str:
    """Return the packaged policy text."""
    return packaged_rules_path().read_text(encoding="utf-8")


__all__ = ["RULES_RESOURCE", "packaged_rules_path", "read_rules_text"]
