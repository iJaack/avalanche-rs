#!/usr/bin/env python3
import json
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: compare_benchmarks.py <baseline.json> <current.json> <max_regression_pct>")
        return 2

    baseline_path, current_path, max_regression_pct = sys.argv[1], sys.argv[2], float(sys.argv[3])
    with open(baseline_path, "r", encoding="utf-8") as f:
        baseline = json.load(f)
    with open(current_path, "r", encoding="utf-8") as f:
        current = json.load(f)

    failures = []
    for key, base_value in baseline.items():
        if key not in current:
            failures.append(f"missing current metric: {key}")
            continue
        cur_value = current[key]
        if not isinstance(base_value, (int, float)) or not isinstance(cur_value, (int, float)):
            failures.append(f"non-numeric metric: {key}")
            continue
        threshold = base_value * (1 + max_regression_pct / 100.0)
        if cur_value > threshold:
            failures.append(
                f"{key} regressed: current={cur_value} baseline={base_value} threshold={threshold:.2f}"
            )

    print("Baseline:", json.dumps(baseline, indent=2))
    print("Current:", json.dumps(current, indent=2))

    if failures:
        print("\nBenchmark regression check failed:")
        for failure in failures:
            print("-", failure)
        return 1

    print("\nBenchmark regression check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
