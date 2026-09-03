"""The causal key: one root cause, one finding (PAL-ROOTCAUSE-01).

Deduplication used to hash 120 raw characters of the analyst's prose. That makes
identity depend on wording: two analysts describing the same defect differently
produce two findings, and one rephrase splits a recurrence chain in half —
destroying exactly the signal recurrence exists to provide.

The causal key normalizes instead. It reduces a description to its stable content
words, drops filler and per-session detail, and orders what remains, so the same
mechanism described twice hashes the same. It is deliberately lossy: a key is for
matching, and the full prose stays on the finding for the maintainer to read.
"""

from __future__ import annotations

import hashlib
import re

#: Words that carry no causal information. Removing them is what makes two
#: descriptions of one mechanism converge. Kept small on purpose: an aggressive
#: list starts merging genuinely different defects.
_STOPWORDS = frozenset(
    """
    a an the this that these those it its is was were be been being are am
    and or but so then than because thus therefore however
    of in on at to from by for with without into onto over under about
    as if not no nor did does do done doing
    there here when while during after before
    which who whom whose what
    may might can could should would will shall must
    just only very really quite simply actually
    one another same such also still yet per each any
    session episode event events seq step steps run runs
    """.split()
)

#: Per-session noise that is real but never part of the mechanism: identifiers,
#: digests, sequence numbers, paths, timestamps.
_NOISE = (
    re.compile(r"\b[0-9a-f]{7,64}\b"),          # digests and object ids
    re.compile(r"\bses_[A-Za-z0-9]+\b"),        # provider session ids
    re.compile(r"\bT-\d+\b"),                   # ticket ids
    re.compile(r"\b\d+\b"),                     # bare numbers
    re.compile(r"[a-zA-Z]:[\\/][^\s]+"),        # windows paths
    re.compile(r"(?<![A-Za-z])/[^\s]+"),        # posix paths
)

_WORD = re.compile(r"[a-z][a-z_\-]*")

#: Morphological endings collapsed so "routed"/"routing"/"routes" agree. A real
#: stemmer would be better and is not worth a dependency here; the cut is
#: conservative and only applied to words long enough to survive it.
_SUFFIXES = ("ingly", "edly", "ing", "ions", "ion", "ed", "es", "s", "ly")

#: Keys of `observed` a detector may fill; used when there is no prose at all.
_OBSERVED_KEYS = ("summary", "canonical", "raw", "command", "to_phase", "from_phase")

MAX_TOKENS = 12


def _stem(word: str) -> str:
    for suffix in _SUFFIXES:
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def normalize_cause(text: object) -> str:
    """A stable, order-independent token signature of one causal description."""
    lowered = str(text or "").lower()
    for pattern in _NOISE:
        lowered = pattern.sub(" ", lowered)
    tokens = [
        _stem(word)
        for word in _WORD.findall(lowered)
        if word not in _STOPWORDS and len(word) > 2
    ]
    unique = sorted({token for token in tokens if token})
    return " ".join(unique[:MAX_TOKENS])


def _from_observed(candidate: dict) -> str:
    observed = candidate.get("observed")
    if not isinstance(observed, dict):
        return ""
    for key in _OBSERVED_KEYS:
        value = observed.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def causal_key(candidate: dict) -> str:
    """The normalized causal signature of this candidate, or `""`."""
    for source in (candidate.get("root_cause"), candidate.get("root_cause_hypothesis")):
        if isinstance(source, str) and source.strip():
            key = normalize_cause(source)
            if key:
                return key
    return normalize_cause(_from_observed(candidate))


def fingerprint(candidate: dict) -> str:
    """Finding identity: rule family + drift class + change target + causal key.

    Session id is deliberately absent (PAL-ROOTCAUSE-01): many sessions may
    support one finding, and that is the whole point of recurrence.
    """
    payload = "|".join(
        (
            str(candidate.get("drift_class") or ""),
            ",".join(sorted(str(rule) for rule in (candidate.get("rule_ids") or []) if rule)),
            str(candidate.get("change_target") or ""),
            causal_key(candidate),
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
