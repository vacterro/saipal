<!-- OWNER: saipal/INDEX.md -->
<!-- RULES: PAL-INDEX-01 -->
# INDEX — the document map

One question, one owner document. Never read the whole protocol; load the
exact document that answers the question you have right now.

## PAL-INDEX-01 — routing table

| Question | Owner document |
| --- | --- |
| How does SAIPAL start? | `BOOT.md` |
| What are the global laws? | `CORE.md` |
| What is the two-layer boundary? | `ARCHITECTURE.md` |
| What commands can I run? | `COMMANDS.md` |
| How do I report drift to the operator? | `COMMANDS.md` (`report`) + `SKILL.md` |
| What is a canonical session bundle? | `SESSIONS.md` |
| What is the finding contract? | `FINDINGS.md` |
| What is the audit contract? | `AUDITS.md` |
| How do I perform semantic analysis? | `ANALYSIS.md` |
| How do I retrieve evidence windows? | `EVIDENCE.md` (future — T-035) |
| What is the agent adapter? | `SKILL.md` |
| What are the closed machine facts? | `REGISTRY.json` |

## Safety routing

Safety questions always route to `CORE.md`:

- Can SAIPAL touch this? → `CORE.md` PAL-WRITE-01
- Is this binding trustworthy? → `CORE.md` PAL-BINDING-01
- Is this evidence admissible? → `CORE.md` PAL-EVIDENCE-01
- Can this finding qualify? → `CORE.md` PAL-DONOHARM-01
- Can I edit an emitted audit? → `CORE.md` PAL-OWNERSHIP-01 (no)
