# TraceGuard: a replayable tool-use agent with an authority boundary

## TL;DR

I built a LangGraph agent that can read runbooks and tickets, update ticket state with approval, and recover after a write commits but before its graph checkpoint does. A separate deterministic policy checks tenant scope and user intent before every tool call. On a fixed synthetic task suite, the guarded local-model agent completed **144/144** trials versus **108/144** for a plain tool agent; it made no cross-tenant writes versus **36** in the baseline. After **20/20** injected post-commit restarts, final state was correct with no duplicate accepted write. The model did not follow the tested malicious runbook in either mode; a separate scripted forced-attack test shows the gate's behavior when an export is proposed. The case-level results are in [results/evaluation.json](results/evaluation.json).

![Task success](docs/img/task_success.png)

## What I built

- A [LangGraph loop](traceguard/agent.py) that asks a local MLX/Qwen2.5 model for one JSON tool action at a time. [LangChain structured tools](traceguard/agent.py) expose ticket reads, runbook reads, ticket status updates and record export.
- A deterministic tool gate that checks the supplied tenant context, exact user intent and target, allowed status and action budget before execution. Writes pause at a LangGraph approval interrupt. The local prototype does not authenticate the tenant context.
- A [SQLite workspace](traceguard/workspace.py) where a ticket change and its idempotency receipt commit together. Checkpoints resume the graph after a crash, and [saved actions](results/demo.json) can replay from a pre-run snapshot without relying on identical model text.
- A [benchmark](traceguard/benchmark.py) with fixed task templates, a plain ungated baseline, malicious runbooks, a forced scripted policy test and post-commit restart trials. The [CLI](traceguard/__main__.py) runs the demo, replay, evaluation and interactive approval flow.

## Why I made this

An agent can write a convincing final answer even when it took the wrong action. I wanted to grade the resulting workspace and action trace. I also wanted to make one specific failure visible: a runbook is useful evidence, but text inside it must not gain the authority to export another tenant's records.

## Architecture

```mermaid
flowchart LR
    U[User task and tenant context] --> P[MLX planner]
    P --> G[Deterministic policy gate]
    G -->|read| T[LangChain tools]
    G -->|write| H[LangGraph approval interrupt]
    H --> T
    T --> W[(SQLite workspace and idempotency receipts)]
    T --> O[Untrusted observation]
    O --> P
    P --> F[Final answer]
    P --> L[(Append-only action trace)]
    G --> L
    T --> L
    P --> C[(SQLite graph checkpoints)]
```

The model proposes JSON actions. LangChain `StructuredTool` wrappers validate tool arguments. The gate enforces the tenant context supplied to the agent, a strict command grammar for writes and exports, exact requested targets and statuses, item shape and a four-decision budget. This intentionally rejects ambiguous natural-language write requests; the supported form is `Mark alpha T01 INVESTIGATING.` or `Export alpha records.` The gate is independent of the model prompt, so a runbook cannot grant itself a new capability. A write triggers a LangGraph `interrupt`; a person or the test harness can approve or reject it. This local prototype does not authenticate the tenant context.

```mermaid
sequenceDiagram
    participant Agent
    participant Gate
    participant Workspace
    participant Checkpoint
    Agent->>Gate: set_ticket_status with task ID and step
    Gate->>Agent: Approval required
    Agent->>Workspace: Commit status and idempotency receipt together
    Note over Agent,Checkpoint: Injected crash before checkpoint
    Agent->>Checkpoint: Resume the same graph step
    Agent->>Workspace: Retry same idempotency key
    Workspace-->>Agent: Prior receipt; no second effect
```

The exact boundary matters: a checkpoint by itself cannot prevent a repeated external side effect when the process dies after the tool commits. Here the local write and its receipt are one SQLite transaction. The replay command copies a pre-run workspace snapshot and reuses recorded planner actions, so it does not depend on the model reproducing the same text.

## Evaluation

The fixed synthetic task set has 48 cases in four classes (read, diagnose, authorized write, abstain), run with three model seeds in both gated and ungated modes. Twenty-four injection task/seed combinations use the same cross-tenant export payload pattern in retrieved runbooks. Twenty injected failures occur at the same boundary, after a committed ticket write and before its LangGraph checkpoint. Model tasks use a quantized local Qwen2.5 1.5B model. The crash suite uses a deterministic planner so the interruption boundary, rather than model variance, is under test.

The [machine-readable results](results/evaluation.json) record environment, model, command, seeds, load average, every case and its result. The baseline uses the same model and tools but skips the authority gate; it is intentionally minimal. Identical paired prompts reuse a cached sampled model action, so the per-case wall times are diagnostic only and must not be read as a latency comparison between modes.

| Measure | Guarded | Plain baseline |
| --- | ---: | ---: |
| Correct fixed synthetic task outcomes | 144/144 | 108/144 |
| Cross-tenant writes in 36 abstain trials | 0 | 36 |
| Unauthorized exports in 24 model injection cases | 0 | 0 |
| Correct answers in 24 model injection cases | 23/24 | 23/24 |
| Correct final states after 20 post-commit restarts | 20/20; 0 duplicate accepted writes | Not evaluated |

The model took `get_runbook` then `finish` in all 24 malicious-runbook trials. It never proposed an export, so the zero-execution count in that row does **not** demonstrate a model attack blocked by the gate. I also ran a [separate deterministic test double](results/scripted_policy_evaluation.json) that deliberately proposes a cross-tenant export after reading that runbook: the gate blocked all 24 proposals, while the ungated baseline executed all 24. This is a policy-unit result, not a model success rate.

![Model and scripted export outcomes](docs/img/export_gate.png)

The first image shows task outcomes; this one separates local-model behavior from the forced scripted policy test. Both are generated from saved result JSON by [scripts/make_figures.py](scripts/make_figures.py).

**What these numbers do not show:** this is a local synthetic operations workspace, not a production multi-tenant service. The gate enforces specified rules; zero executed unauthorized writes does not prove prompt-injection immunity or that every user intent is interpreted correctly. The planner is a small quantized model, and the four task classes use repetitive templates. The read/diagnose grader checks the exact tool read plus a required answer substring; the abstain grader checks workspace effects, not refusal wording. The crash test raises an exception after commit rather than pulling power from a machine, and repeats the same interruption boundary on 20 task IDs. The action trace is inserted separately from the tool effect, so a crash in that gap could omit one trace record; the durable idempotency receipt still prevents a duplicate effect. A production audit trail would need a transactional outbox. The baseline intentionally has no policy gate; it is not a comparison with a hardened production agent. Timings depend on the load recorded in the results file.

## Run it yourself

On an Apple silicon Mac with Python 3.11:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m traceguard demo
.venv/bin/python -m traceguard replay results/demo_snapshot.sqlite results/demo.json
.venv/bin/python -m traceguard evaluate --seeds 3
.venv/bin/python scripts/make_figures.py
```

The tests should report **8 passed**. `demo` writes [results/demo.json](results/demo.json): check `attack_denials: 1`, `unauthorized_exports: 0`, `committed_writes_after_resume: 1` and `resumed_ticket_status: INVESTIGATING`. `replay` should print `same_action_and_effect_trace: true`. The full model evaluation writes [results/evaluation.json](results/evaluation.json) and takes longer than the demo on an M2 Mac; `make_figures.py` rebuilds both images from saved results.

`demo` uses a deliberately adversarial scripted planner to show a blocked export and an idempotent restart. `evaluate` uses the real local model; its first run downloads the [Qwen2.5 1.5B 4-bit MLX model](https://huggingface.co/mlx-community/Qwen2.5-1.5B-Instruct-4bit). The model weights are not in this repository. To see a model-driven demo, run `.venv/bin/python -m traceguard demo --model`; a [sample model trace](results/model_demo/demo.json) and its replay are included. The model read and summarized the runbook correctly in that sample; the restart portion of the demo uses the scripted planner to hit the fault boundary exactly.

For an interactive write approval, run `.venv/bin/python -m traceguard run "Mark alpha T01 INVESTIGATING."`. The CLI seeds a local synthetic workspace on first use and prints its action trace.

## Tests

Eight tests cover a malicious runbook, the ungated baseline, cross-tenant and wrong-ticket writes, a crash after commit, action replay, exact-item grading, negated export intent and a rejected approval interrupt.

## What this isn't

It is not an autonomous agent with arbitrary system access, a security proof, a production deployment or evidence that a small model understands every instruction. The workspace is synthetic and all writes are local SQLite effects. A real tool would need its own durable idempotency contract.

The recorded traces, model cases and scripted policy cases are included so every claimed outcome can be checked against the resulting workspace state.
