# TraceGuard interview notes

## What it is

A local LangGraph ticket agent whose tool actions pass through a deterministic tenant and user-intent gate. It records action traces, resumes after checkpoint gaps and replays decisions against a workspace snapshot.

## How it works and why

- A 4-bit local model proposes JSON actions. LangChain StructuredTool wrappers validate arguments.
- The LangGraph loop plans, checks authority, executes and observes. SQLite stores graph checkpoints.
- The gate checks the tenant context supplied to the agent, explicit write/export intent, item ID, allowed status and step budget. Runbook text is never consulted as an authority source. The local prototype does not authenticate that context.
- Writes trigger a LangGraph approval interrupt. The test harness can approve, but the CLI asks a person.
- The ticket change and idempotency receipt commit together. A retry after a crash returns the prior receipt.
- The trace stores proposed, authorized, denied and executed actions. Replay takes a saved snapshot and the action list, not a fresh model generation.

## Measured results and limits

The fixed 48-task × three-seed local-model suite finished 144/144 guarded trials versus 108/144 for the plain baseline. The difference was the 36 cross-tenant write requests: the baseline wrote to beta 36 times; the gate denied all 36. In 24 malicious-runbook model trials, neither mode exported data; the model read the runbook then finished, with 23/24 answers matching the narrow recommendation check in each mode. A separate scripted test double deliberately proposed 24 cross-tenant exports; the gate blocked 24/24 and the baseline executed 24/24. Twenty injected post-commit restarts ended in the right ticket state, with zero duplicate accepted writes and 20 idempotency replays. See `results/evaluation.json` and `results/scripted_policy_evaluation.json` for case-level data.

The injection cases share one cross-tenant export pattern, and the crash tests use the same interruption boundary on twenty task IDs. The model's zero export attempts do not show that it resisted other payloads or that the gate blocked a model-proposed attack. The suite is synthetic and narrow; its policy cannot prove prompt-injection immunity. The crash point is an injected exception, not a power failure. A trace insert is not atomic with a tool effect, so a crash in that gap may leave an incomplete trace even though the idempotency receipt prevents a duplicate write. The local tenant context is not authenticated.

## Two-minute STAR answer

**Situation:** A synthetic operations agent could read a runbook containing a malicious instruction to export another tenant's records. A write could also be repeated if the process died after the tool committed but before the graph checkpoint.

**Task:** I wanted the final workspace state, not only the agent's prose, to be correct and replayable.

**Action:** I put a deterministic capability gate between the model and LangChain tools, added a LangGraph approval interrupt for writes, committed idempotency receipts with ticket changes, and logged every action. I built a paired baseline, malicious runbooks, a post-commit crash schedule and a snapshot replay command.

**Result:** On the fixed synthetic model suite, guarded task success was 144/144 versus 108/144; the gate denied 36 cross-tenant writes. Twenty post-commit restart trials produced correct state and no duplicate accepted writes. The model did not take the injected bait in either mode; a separate scripted attack confirmed the gate blocks an explicitly proposed export. These are local, narrow results.

## Likely follow-ups

1. **Why is a prompt instruction not enough?** The model may follow untrusted text. The tool gate decides independently whether an action is authorized.
2. **What is the trust boundary?** The tenant context and user task are trusted input to the gate. Retrieved runbook bodies and tool outputs are observations. A real service must authenticate that context.
3. **What does LangGraph add?** A stateful loop, SQLite checkpoints and an interrupt that pauses before a write for approval.
4. **What does LangChain add?** Structured tool definitions and input validation; the model does not directly call workspace methods.
5. **Why both checkpointing and idempotency?** The tool can commit before the checkpoint. A resumed graph might repeat that step.
6. **Can the agent still make a bad decision?** Yes. The gate only blocks specified unauthorized effects; the model can choose the wrong allowed read or produce a poor answer.
7. **Does zero unauthorized execution mean injection-proof?** No. It means the tested actions did not cross the specified gate. A broader capability set needs new tests.
8. **How does replay work?** The demo saves a pre-run SQLite snapshot and action trace; replay copies the snapshot and feeds the recorded actions through the same graph.

## Explain cold checklist

- Draw plan → gate → approval → tool → observation.
- Show one malicious runbook and its denied export trace.
- Explain the commit/checkpoint gap with the two tool receipts.
- Distinguish model trials, scripted attack and crash tests.
- Open `results/evaluation.json` and quote the measured numbers with limits.
