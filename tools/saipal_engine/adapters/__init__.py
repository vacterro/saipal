from __future__ import annotations

from . import claude
from . import codex
from . import gemini
from . import generic
from . import opencode
from . import termisai
from .jsonl_evidence import jsonl_window
from ..errors import PalError

ADAPTER_REGISTRY = {
    "generic": generic,
    "claude": claude,
    "codex": codex,
    "opencode": opencode,
    "termisai": termisai,
    "gemini": gemini,
}


def read_evidence(
    adapter: str,
    source_ref: str,
    locator: dict,
    *,
    before: int,
    after: int,
    registry: dict,
) -> dict:
    """Common read-only adapter evidence boundary; unsupported stays honest."""
    module = ADAPTER_REGISTRY.get(adapter)
    reader = getattr(module, "read_evidence", None) if module is not None else None
    if reader is None:
        raise PalError(
            "EVIDENCE_UNSUPPORTED",
            f"adapter {adapter!r} has no evidence reader",
            next_action="use a provider with a registered evidence interface",
        )
    return reader(source_ref, locator, before=before, after=after, registry=registry)

__all__ = [
    "ADAPTER_REGISTRY",
    "read_evidence",
    "jsonl_window",
    "generic",
    "claude",
    "codex",
    "opencode",
    "termisai",
    "gemini",
]
