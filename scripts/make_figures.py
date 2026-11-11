"""Render task and policy plots from saved model and scripted result JSON."""

import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "results/evaluation.json").read_text())
counts = defaultdict(lambda: {"guarded": [0, 0], "baseline": [0, 0]})
for case in data["cases"]:
    slot = counts[case["kind"]]["guarded" if case["guarded"] else "baseline"]
    slot[0] += int(case["correct"])
    slot[1] += 1

kinds = list(counts)
fig, ax = plt.subplots(figsize=(8, 4.5))
x = range(len(kinds))
for offset, label in ((-0.2, "baseline"), (0.2, "guarded")):
    ax.bar(
        [i + offset for i in x],
        [100 * counts[k][label][0] / counts[k][label][1] for k in kinds],
        0.4, label=label,
    )
ax.set_xticks(list(x), kinds)
ax.set_ylim(0, 105)
ax.set_ylabel("Task success (%)")
ax.set_title("Fixed synthetic agent tasks")
ax.legend()
fig.tight_layout()
out = ROOT / "docs/img/task_success.png"
out.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(out, dpi=170)
print(out)
plt.close(fig)

scripted = json.loads((ROOT / "results/scripted_policy_evaluation.json").read_text())
groups = [
    ("Local model", data["attacks"]),
    ("Forced scripted action", scripted["attacks"]),
]
baseline_exports = [sum(c["unauthorized_exports"] for c in rows if not c["guarded"]) for _, rows in groups]
guarded_exports = [sum(c["unauthorized_exports"] for c in rows if c["guarded"]) for _, rows in groups]
fig, ax = plt.subplots(figsize=(8, 3.7))
positions = range(len(groups))
ax.scatter(baseline_exports, [i - 0.18 for i in positions], s=180, color="#d97757", label="Plain baseline")
ax.scatter(guarded_exports, [i + 0.18 for i in positions], s=180, color="#248a60", label="Guarded")
for i, (base, guard) in enumerate(zip(baseline_exports, guarded_exports)):
    ax.text(base + 0.7, i - 0.18, str(base), va="center")
    ax.text(guard + 0.7, i + 0.18, str(guard), va="center")
ax.set_yticks(list(positions), [name for name, _ in groups])
ax.invert_yaxis()
ax.set_xlim(-1, max(baseline_exports + guarded_exports) * 1.15 + 1)
ax.set_xlabel("Executed unauthorized exports in 24 paired cases")
ax.set_title("Runbook injection: model behavior vs forced policy test")
ax.legend()
fig.tight_layout()
out = ROOT / "docs/img/export_gate.png"
fig.savefig(out, dpi=170)
print(out)
