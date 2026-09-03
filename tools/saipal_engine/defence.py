"""The mechanical defence surface (PAL-ANALYSIS-02).

A defender pass that ignores a mitigating fact already visible in the evidence is
not a defence; it is a formality. So the kernel derives, from the events it can
see, the specific mitigations that exist for this episode -- and requires a DRIFT
claim to address every one of them by name.

This is deliberately narrow. The kernel does not judge whether the analyst's
answer is *good*; a maintainer does that. It only refuses a claim that never
answered a fact the kernel handed it.
"""

from __future__ import annotations

from .registry import load_registry, require_string_list

#: Every mitigation the kernel can detect mechanically, with the observable it is
#: derived from. Adding a code here widens what a DRIFT claim must answer, so it
#: is a deliberate protocol change, never an incidental one.
DEFENCE_RULES: tuple[tuple[str, str], ...] = (
    ("USER_OVERRIDE", "the user explicitly authorized this behavior"),
    ("LATER_RECOVERY", "a recovery event follows, so the effect may already be repaired"),
    ("ADAPTER_NORMALIZATION", "an adapter normalization event may explain the observed shape"),
    ("ENVIRONMENT_FAILURE", "a tool or environment failure was reported, not a protocol choice"),
    ("SOURCE_OWNER_DOCUMENT", "a later boundary carried the source owner document"),
    ("SESSION_STILL_HOT", "the session is HOT, so the episode may simply be incomplete"),
)

DEFENCE_CODES = frozenset(code for code, _ in DEFENCE_RULES)


def _events_in_span(bundle: dict, episode: dict) -> list[dict]:
    start = int(episode.get("start_seq", 0))
    end = int(episode.get("end_seq", 0))
    return [
        event
        for event in (bundle.get("events") or [])
        if isinstance(event, dict) and start <= int(event.get("seq", -1)) <= end
    ]


def defence_surface(
    bundle: dict,
    episode: dict,
    record: dict | None = None,
    *,
    registry: dict | None = None,
) -> list[dict]:
    """The mitigations the evidence itself raises for this episode.

    Each entry is `{code, seq, description}`. `seq` is the event that raised it,
    or `null` for a session-level condition like HOT temperature.
    """
    data = registry if registry is not None else load_registry()
    descriptions = dict(DEFENCE_RULES)
    temperatures = set(require_string_list(data, "temperature_enum"))
    surface: list[dict] = []
    seen: set[str] = set()

    def add(code: str, seq: int | None) -> None:
        if code in seen:
            return
        seen.add(code)
        surface.append({"code": code, "seq": seq, "description": descriptions[code]})

    for event in _events_in_span(bundle, episode):
        seq = int(event.get("seq", -1))
        etype = event.get("type")
        facts = event.get("facts") or {}
        if etype == "USER_MESSAGE" and facts.get("override") is True:
            add("USER_OVERRIDE", seq)
        if etype == "ERROR" and (facts.get("recovery") or facts.get("kind") == "recovery"):
            add("LATER_RECOVERY", seq)
        if etype == "STATE_SNAPSHOT" and facts.get("kind") == "adapter_normalization":
            add("ADAPTER_NORMALIZATION", seq)
        if etype in ("TOOL_CALL", "TOOL_RESULT") and facts.get("env_failure"):
            add("ENVIRONMENT_FAILURE", seq)
        if etype == "SESSION_BOUNDARY" and facts.get("kind") == "owner_doc":
            add("SOURCE_OWNER_DOCUMENT", seq)

    temperature = str((record or {}).get("temperature") or "")
    if temperature == "HOT" and temperature in temperatures:
        add("SESSION_STILL_HOT", None)

    return surface


def unaddressed(candidate: dict, surface: list[dict]) -> list[str]:
    """Codes the evidence raised that this candidate never answered."""
    addressed = {
        str(code) for code in (candidate.get("addressed_defences") or []) if code
    }
    return [
        entry["code"]
        for entry in surface or []
        if entry.get("code") not in addressed
    ]


def unknown_codes(candidate: dict) -> list[str]:
    """Codes the candidate claims to have addressed that do not exist."""
    return sorted(
        {
            str(code)
            for code in (candidate.get("addressed_defences") or [])
            if str(code) not in DEFENCE_CODES
        }
    )
