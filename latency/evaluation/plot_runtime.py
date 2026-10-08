import matplotlib.pyplot as plt
import os
import json
import statistics
from pathlib import Path

results = {
    "normal": [],
    "parallel": []
}

TIMEOUT = 90
RESULTS_DIR = Path(__file__).resolve().parent / "results_runtime"
OUTPUT = Path(__file__).resolve().parents[1] / "analysis" / "runtime.svg"

for s in os.listdir(RESULTS_DIR):
    if s.endswith(".json"):
        kind = s.split("_")[0]
        delay = float(s.split("_")[1].split(".json")[0])
        j = json.loads(open(os.path.join(RESULTS_DIR, s)).read())
        data = [r["stats"]["runtime"] if r["success"] else TIMEOUT for r in j]
        results[kind].append((delay, statistics.median(data)))

results["normal"].sort()
results["parallel"].sort()

x_normal = [r[0] for r in results["normal"]]
y_normal = [r[1] for r in results["normal"]]

x_parallel = [r[0] for r in results["parallel"]]
y_parallel = [r[1] for r in results["parallel"]]

print(x_normal)
print(x_parallel)

plt.plot(x_normal, y_normal, ".--", label = "normal")
plt.plot(x_parallel, y_parallel, ".--", label = "parallel")
plt.xscale("log")
plt.xlabel("network delay [ms]")
plt.ylabel("median attack time [s]")
plt.legend()
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
plt.savefig(OUTPUT)
plt.show()
