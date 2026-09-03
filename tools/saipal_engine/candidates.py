"""The structured semantic candidate: the ONLY thing Layer B may submit.

A candidate is a strict, closed, machine-validated document. It is not prose,
not a patch, not a command. Layer A validates the shape and the claim
discipline; nothing inside a candidate can widen what the kernel may do.

Validation is deliberately unforgiving. Layer B is a replaceable model, and a
model that guesses a field name is telling the kernel it does not know the
contract -- accepting the guess is how a forensic tool starts inventing findings.
"""

from __future__ import annotations

from .registry import (
    load_registry,
    require_mapping,
    require_string_list,
)
from . import defence as defence_mod
from . import disposition as disposition_mod

CANDIDATE_SCHEMA_KEY = "candidate_schema_version"

#: A no-drift result is still a submission: it advances the semantic watermark
#: and it is the receipt that proves an episode was actually examined.
VERDICT_DRIFT = "DRIFT"
VERDICT_NO_DRIFT = "NO_DRIFT"
VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"


def _limits(registry: dict) -> dict[str, int]:
    return {
        key: int(value)
        for key, value in require_mapping(registry, "candidate_limits").items()
    }


def _text_problems(
    value: object, field: str, *, limit: int, required: bool
) -> list[str]:
    if value is None or value == "":
        return [f"{field} is required"] if required else []
    if not isinstance(value, str):
        return [f"{field} must be a string"]
    stripped = value.strip()
    if required and not stripped:
        return [f"{field} is required"]
    if len(value) > limit:
        return [f"{field} exceeds {limit} characters"]
    return []


def _list_problems(
    value: object, field: str, *, max_items: int, max_chars: int
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        return [f"{field} must be an array"]
    problems: list[str] = []
    if len(value) > max_items:
        problems.append(f"{field} exceeds {max_items} items")
    for position, item in enumerate(value):
        if not isinstance(item, str):
            problems.append(f"{field}[{position}] must be a string")
        elif len(item) > max_chars:
            problems.append(f"{field}[{position}] exceeds {max_chars} characters")
    return problems


def _challenge_problems(value: object, limits: dict[str, int]) -> list[str]:
    """PAL-ANALYSIS-02: prosecutor, defender, and why the loser lost."""
    if not isinstance(value, dict):
        return ["challenge must be an object"]
    problems: list[str] = []
    for field in ("prosecutor", "defender", "winner", "loser_rejection"):
        problems += _text_problems(
            value.get(field),
            f"challenge.{field}",
            limit=limits["max_reasoning_chars"],
            required=True,
        )
    winner = value.get("winner")
    if isinstance(winner, str) and winner not in ("prosecutor", "defender"):
        problems.append("challenge.winner must be 'prosecutor' or 'defender'")
    for name in sorted(
        set(value) - {"prosecutor", "defender", "winner", "loser_rejection"}
    ):
        problems.append(f"challenge has unknown field {name!r}")
    return problems


def candidate_problems(candidate: object, *, registry: dict | None = None) -> list[str]:
    """Every reason this candidate is inadmissible, or an empty list.

    Shape first, then claim discipline: an unknown field, an enum outside its
    closed set, a missing challenge on a claim that requires one, or evidence
    that points outside the episode it was handed.
    """
    data = registry if registry is not None else load_registry()
    limits = _limits(data)
    fields = set(require_string_list(data, "candidate_fields"))
    required = set(require_string_list(data, "candidate_required_fields"))
    verdicts = set(require_string_list(data, "candidate_verdicts"))
    drift_classes = set(require_string_list(data, "drift_taxonomy"))
    dispositions = set(require_string_list(data, "disposition_class"))
    targets = set(require_string_list(data, "change_target_enum"))
    confidences = set(require_string_list(data, "confidence_enum"))
    severities = set(require_string_list(data, "severity_enum"))
    expected_schema = int(data.get(CANDIDATE_SCHEMA_KEY, 1))

    if not isinstance(candidate, dict):
        return ["candidate root is not an object"]

    problems: list[str] = []
    if candidate.get("schema_version") != expected_schema:
        problems.append(
            f"schema_version {candidate.get('schema_version')!r} != {expected_schema}"
        )
    for name in sorted(required - set(candidate)):
        problems.append(f"missing required field {name!r}")
    for name in sorted(set(candidate) - fields):
        problems.append(f"unknown candidate field {name!r}")

    verdict = candidate.get("verdict")
    if verdict not in verdicts:
        problems.append(f"verdict {verdict!r} outside {sorted(verdicts)}")

    problems += _text_problems(
        candidate.get("unit_digest"), "unit_digest", limit=64, required=True
    )
    problems += _text_problems(
        candidate.get("session_id"), "session_id", limit=512, required=True
    )
    episode_index = candidate.get("episode_index")
    if not isinstance(episode_index, int) or isinstance(episode_index, bool):
        problems.append("episode_index must be an integer")
    elif episode_index < 0:
        problems.append("episode_index must not be negative")

    disposition = candidate.get("disposition_class")
    if disposition not in dispositions:
        problems.append(
            f"disposition_class {disposition!r} outside {sorted(dispositions)}"
        )

    problems += _text_problems(
        candidate.get("reasoning"),
        "reasoning",
        limit=limits["max_reasoning_chars"],
        required=True,
    )
    problems += _list_problems(
        candidate.get("rule_ids"),
        "rule_ids",
        max_items=limits["max_rule_ids"],
        max_chars=64,
    )
    problems += _list_problems(
        candidate.get("alternatives"),
        "alternatives",
        max_items=limits["max_list_items"],
        max_chars=limits["max_text_chars"],
    )
    problems += _list_problems(
        candidate.get("contrary_evidence"),
        "contrary_evidence",
        max_items=limits["max_list_items"],
        max_chars=limits["max_text_chars"],
    )
    problems += _list_problems(
        candidate.get("missing_evidence"),
        "missing_evidence",
        max_items=limits["max_list_items"],
        max_chars=limits["max_text_chars"],
    )
    problems += _list_problems(
        candidate.get("protected_invariants"),
        "protected_invariants",
        max_items=limits["max_list_items"],
        max_chars=limits["max_text_chars"],
    )
    problems += _list_problems(
        candidate.get("addressed_defences"),
        "addressed_defences",
        max_items=limits["max_list_items"],
        max_chars=64,
    )
    unknown = defence_mod.unknown_codes(candidate)
    if unknown:
        problems.append(
            f"addressed_defences names unknown code(s) {unknown}; admissible codes are "
            f"{sorted(defence_mod.DEFENCE_CODES)}"
        )

    refs = candidate.get("event_refs")
    if refs is None:
        refs = []
    if not isinstance(refs, list):
        problems.append("event_refs must be an array")
    else:
        if len(refs) > limits["max_event_refs"]:
            problems.append(f"event_refs exceeds {limits['max_event_refs']} items")
        for position, ref in enumerate(refs):
            if not isinstance(ref, int) or isinstance(ref, bool):
                problems.append(f"event_refs[{position}] must be an integer")

    problems += _drift_problems(
        candidate,
        verdict,
        drift_classes=drift_classes,
        targets=targets,
        confidences=confidences,
        severities=severities,
        limits=limits,
    )
    # PAL-ANALYSIS-03: the disposition class must agree with the verdict and with
    # the change surface it proposes. Checked here so an inadmissible pairing
    # never reaches the finding lifecycle at all.
    if verdict in verdicts and disposition in dispositions:
        problems += disposition_mod.disposition_problems(
            verdict, disposition, candidate.get("change_target"), registry=data
        )
    return problems


def _drift_problems(
    candidate: dict,
    verdict: object,
    *,
    drift_classes: set,
    targets: set,
    confidences: set,
    severities: set,
    limits: dict[str, int],
) -> list[str]:
    """Claim discipline: what a DRIFT verdict must carry that NO_DRIFT must not.

    A no-drift receipt that names a drift class and a change target is not a
    no-drift receipt; it is a finding with the label filed off. The asymmetry is
    the point, so it is checked in both directions.
    """
    problems: list[str] = []
    claim_fields = (
        "drift_class",
        "severity",
        "confidence",
        "change_target",
        "root_cause",
        "challenge",
        "addressed_defences",
    )

    if verdict != VERDICT_DRIFT:
        # A no-drift receipt may cite the events it examined -- that is evidence
        # of work, not a claim. Everything in claim_fields is refused.
        for field in claim_fields:
            if candidate.get(field) not in (None, "", [], {}):
                problems.append(
                    f"{field} is only admissible on a {VERDICT_DRIFT} verdict"
                )
        return problems

    if candidate.get("drift_class") not in drift_classes:
        problems.append(
            f"drift_class {candidate.get('drift_class')!r} outside the taxonomy"
        )
    if candidate.get("severity") not in severities:
        problems.append(f"severity {candidate.get('severity')!r} outside {sorted(severities)}")
    if candidate.get("confidence") not in confidences:
        problems.append(
            f"confidence {candidate.get('confidence')!r} outside {sorted(confidences)}"
        )
    if candidate.get("change_target") not in targets:
        problems.append(
            f"change_target {candidate.get('change_target')!r} outside {sorted(targets)}"
        )
    problems += _text_problems(
        candidate.get("root_cause"),
        "root_cause",
        limit=limits["max_text_chars"],
        required=True,
    )
    if not candidate.get("rule_ids"):
        problems.append("a DRIFT verdict must name at least one rule id")
    if not candidate.get("event_refs"):
        problems.append("a DRIFT verdict must cite at least one event")
    problems += _challenge_problems(candidate.get("challenge"), limits)
    if not candidate.get("alternatives"):
        problems.append(
            "a DRIFT verdict must record at least one alternative explanation"
        )
    return problems


def episode_scope_problems(
    candidate: dict, carrier: dict, *, registry: dict | None = None
) -> list[str]:
    """The candidate must answer the unit it was handed, over that unit's evidence."""
    problems: list[str] = []
    if not isinstance(carrier, dict) or carrier.get("session") is None:
        return ["carrier does not name an analysis unit"]

    session = carrier.get("session") or {}
    episode = carrier.get("episode") or {}
    if candidate.get("session_id") != session.get("session_id"):
        problems.append(
            f"candidate session {candidate.get('session_id')!r} is not the carrier's "
            f"session {session.get('session_id')!r}"
        )
    if candidate.get("episode_index") != episode.get("index"):
        problems.append(
            f"candidate episode {candidate.get('episode_index')!r} is not the carrier's "
            f"episode {episode.get('index')!r}"
        )
    if candidate.get("unit_digest") != carrier.get("unit_digest"):
        problems.append(
            "unit_digest does not match the carrier; the evidence changed under "
            "the analyst and the reasoning is stale"
        )

    start = episode.get("start_seq")
    end = episode.get("end_seq")
    if isinstance(start, int) and isinstance(end, int):
        for ref in candidate.get("event_refs") or []:
            if isinstance(ref, int) and not (start <= ref <= end):
                problems.append(
                    f"event_refs {ref} lies outside the episode span {start}-{end}"
                )

    # PAL-ANALYSIS-02: a DRIFT claim must answer every mitigation the evidence
    # itself raises. Checked against the carrier, because that is where the
    # mechanically derived defence surface lives.
    if candidate.get("verdict") == VERDICT_DRIFT:
        missed = defence_mod.unaddressed(candidate, carrier.get("defence_surface") or [])
        if missed:
            problems.append(
                "the defence surface raises mitigation(s) the claim never addressed: "
                f"{missed}; name them in addressed_defences and answer them in the "
                "defender pass"
            )
    return problems


def normalize_candidate(candidate: dict, *, registry: dict | None = None) -> dict:
    """The validated candidate as the kernel will store it: closed set, no extras."""
    data = registry if registry is not None else load_registry()
    fields = require_string_list(data, "candidate_fields")
    out = {name: candidate[name] for name in fields if name in candidate}
    out["schema_version"] = int(data.get(CANDIDATE_SCHEMA_KEY, 1))
    for name in ("rule_ids", "alternatives", "contrary_evidence", "missing_evidence",
                 "protected_invariants", "event_refs"):
        if name in out and isinstance(out[name], list):
            out[name] = list(out[name])
    return out
