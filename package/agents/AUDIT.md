# Agent Audit — Status of `agents/` Definitions

Generated 2026-06-23. Updated 2026-06-23 (v1.2.0) — orchestrator agent now
has full I/O contract; status table reflects all 4 agents.

## Per-agent status

| Agent | Status | Role clarity | Workflow | I/O contract | Cross-refs to skill/commands |
|-------|--------|--------------|----------|--------------|------------------------------|
| `orchestrator.md` | ✅ functional | ✅ | ✅ | ✅ | ✅ |
| `auditor.md` | ✅ functional | ✅ | ✅ 7-step | ✅ | ✅ |
| `formal-verifier.md` | ✅ functional | ✅ | ✅ 5-step | ✅ | ✅ |
| `report-writer.md` | ✅ functional | ✅ | ✅ 6-step | ✅ | ✅ |

All four agents now have explicit Input / Output / Handoff sections. The orchestrator
routes user requests to the appropriate specialist(s) based on SKILL.md phase routing.

## Coverage matrix

| User request | Command | Primary agent | Secondary |
|--------------|---------|---------------|-----------|
| "audit this program" | `/audit` | auditor | formal-verifier (phase 3), report-writer (phase 5) |
| "quick scan" | `/audit-quick` | auditor | — |
| "prove this invariant" | phase 3 only | formal-verifier | — |
| "generate the report" | `/audit-report` | report-writer | — |
| "write a PoC" | `/audit-poc` | auditor | — |
| "list findings" | `/audit-findings` | (no agent; pure data) | — |
