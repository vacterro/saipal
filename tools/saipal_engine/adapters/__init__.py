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


#: T-103 closed vocabulary for watermark probe semantics. Every adapter
#: declares exactly one of these. The probe never independently suppresses
#: forensic normalization unless it is a MUTATION_SAFE_CHANGE_TOKEN.
WATERMARK_NONE = "NONE"
WATERMARK_APPEND_ONLY_HINT = "APPEND_ONLY_HINT"
WATERMARK_MUTATION_SAFE_CHANGE_TOKEN = "MUTATION_SAFE_CHANGE_TOKEN"


#: Adapters that ship with a probe the dispatcher may trust to hide
#: historical mutation. Empty today: all shipped probes are append hints.
#: A future adapter earns a place here only with a defensible, documented
#: provider guarantee -- never because a function exists.


def watermark_capability(module) -> dict:
    """The capability declaration for an adapter module.

    The dispatcher uses this to decide whether the probe alone is enough to
    skip normalization, or whether a stronger identity check is required.
    Returns a closed-shape dict so callers cannot reach for undeclared
    metadata (T-103, ROLE 4/5).
    """
    declared = getattr(module, "WATERMARK_CAPABILITY", WATERMARK_NONE)
    if declared == WATERMARK_MUTATION_SAFE_CHANGE_TOKEN:
        return {
            "available": True,
            "mutation_safe": True,
            "kind": WATERMARK_MUTATION_SAFE_CHANGE_TOKEN,
        }
    if declared == WATERMARK_APPEND_ONLY_HINT:
        return {
            "available": True,
            "mutation_safe": False,
            "kind": WATERMARK_APPEND_ONLY_HINT,
        }
    return {"available": False, "mutation_safe": False, "kind": WATERMARK_NONE}


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
    "watermark_capability",
    "WATERMARK_NONE",
    "WATERMARK_APPEND_ONLY_HINT",
    "WATERMARK_MUTATION_SAFE_CHANGE_TOKEN",
    "generic",
    "claude",
    "codex",
    "opencode",
    "termisai",
    "gemini",
]
