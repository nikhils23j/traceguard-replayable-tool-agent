"""Render benchmark plots solely from results/evaluation.json."""

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
