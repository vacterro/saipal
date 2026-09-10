"""SAIPAL Layer B runtime -- the replaceable semantic analyst.

This package is deliberately NOT part of `saipal_engine`. The deterministic
kernel (Layer A) owns evidence identity, session state, bindings, validation
and every write; it never interprets meaning and never calls a semantic model.
This package owns the opposite half: it orchestrates an untrusted text-only
model, builds bounded analysis packets, validates the model's structured
output, and enters the kernel exclusively through the existing
`submit_candidate` boundary.

The kernel must never import this package; the model process it drives has no
tools, no filesystem write path and no SAIPAL or SAIPEN authority of its own.
"""

from __future__ import annotations

RUNTIME_VERSION = 1
