# TERMISAI Evidence Contract

SAIPAL reads TERMISAI evidence as append-only JSONL files configured by `sources.json`. This contract is file-based because no stable producer export is available in the inspected TERMISAI tree.

## Record

Each non-empty line is a JSON object. `type`, `seq`, `ts`, `content`, `model`, `provider`, `protocol`, `project`, and `closed` are optional observable fields. `content` is never copied to canonical evidence; only a bounded excerpt digest is retained.

## Identity and generations

Source identity is absolute configured source path plus file digest. Session identity is filename stem. A changed cold artifact becomes a new generation; an append-only hot artifact extends its existing generation. Canonical output is stored under SAIPAL `.saipal/session_inbox/`, never beside raw evidence.

## Hot/cold rule

JSONL is HOT unless a final `closed: true` record is present. The adapter reads complete JSON lines only. A final incomplete line is deferred. Rewriting an already analyzed prefix produces a conflict and freezes analysis.

## Ordering, rotation, protocol

`seq` must strictly increase after normalization. Missing sequence uses physical line order. Rotated files are distinct source identities. Protocol binding metadata is copied only when explicitly present, but Layer A derives its proof level: an exact `git_head` must be resolved by configured protocol authority; version plus a SHA-256 registry digest or a SHA-256 tree fingerprint may supply lower proof; otherwise the result is partial or `UNKNOWN`. SAIPAL never substitutes its current protocol or trusts a caller-declared `BOUND` value.

## Capabilities

`tool_calls: yes`, `tool_results: yes`, `file_writes: partial`, `phase_changes: partial`, `model_identity: partial`, `protocol_binding: exact/partial/unknown`, `timestamps: partial`, `session_completion: explicit-only`.

## Safety

Raw source is read-only. Canonical facts contain digest and at most 2000 characters. Secrets and transcript bodies do not cross the bundle boundary. Malformed records are rejected per source without aborting other sources.
