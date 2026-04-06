"""
PromptWall benchmark eval script
Usage:
    python -m benchmark.run_eval --layer heuristic
    python -m benchmark.run_eval --layer embedding
    python -m benchmark.run_eval --layer full
    python -m benchmark.run_eval --layer all   # runs all configs and prints comparison table
"""
import json
import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from promptwall.layers import heuristic, embedding
from promptwall.firewall import Firewall


def load_dataset(path: str) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


# ------------------------------------------------------------------
# Layer evaluators
# ------------------------------------------------------------------

def eval_heuristic(attacks: list, safe: list) -> dict:
    tp = fp = tn = fn = 0
    times = []
    for sample in attacks:
        t0 = time.perf_counter()
        result = heuristic.scan(sample["prompt"])
        times.append(time.perf_counter() - t0)
        if result and result.is_blocked:
            tp += 1
        else:
            fn += 1
    for sample in safe:
        result = heuristic.scan(sample["prompt"])
        if result and result.is_blocked:
            fp += 1
        else:
            tn += 1
    return _metrics(tp, fp, tn, fn, times, len(attacks), len(safe))


def eval_embedding(attacks: list, safe: list) -> dict:
    """L1 + L2 — heuristic then embedding."""
    try:
        embedding.preload()
    except Exception as e:
        print(f"[warn] embedding preload failed: {e}")

    tp = fp = tn = fn = 0
    times = []

    for sample in attacks:
        t0 = time.perf_counter()
        # L1 first
        r = heuristic.scan(sample["prompt"])
        if not (r and r.is_blocked):
            # L2
            r = embedding.scan(sample["prompt"])
        times.append(time.perf_counter() - t0)
        if r and r.is_blocked:
            tp += 1
        else:
            fn += 1

    for sample in safe:
        r = heuristic.scan(sample["prompt"])
        if not (r and r.is_blocked):
            r = embedding.scan(sample["prompt"])
        if r and r.is_blocked:
            fp += 1
        else:
            tn += 1

    return _metrics(tp, fp, tn, fn, times, len(attacks), len(safe))


def eval_full(attacks: list, safe: list, provider: str = "local", model: str = None) -> dict:
    """Full stack — L1 + L2 + L3 via Firewall."""
    fw = Firewall(provider=provider, model=model, verbose=False)
    tp = fp = tn = fn = 0
    times = []

    for sample in attacks:
        t0 = time.perf_counter()
        result = fw.scan(sample["prompt"])
        times.append(time.perf_counter() - t0)
        if result.is_blocked:
            tp += 1
        else:
            fn += 1

    for sample in safe:
        result = fw.scan(sample["prompt"])
        if result.is_blocked:
            fp += 1
        else:
            tn += 1

    return _metrics(tp, fp, tn, fn, times, len(attacks), len(safe))


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _metrics(tp, fp, tn, fn, times, n_attacks, n_safe) -> dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    avg_ms    = (sum(times) / len(times) * 1000) if times else 0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "avg_ms":    round(avg_ms, 1),
        "total_attacks": n_attacks,
        "total_safe":    n_safe,
    }


def print_results(results: dict, label: str):
    print(f"\n{'='*44}")
    print(f"  PromptWall — {label}")
    print(f"{'='*44}")
    print(f"  Dataset   : {results['total_attacks']} attacks, {results['total_safe']} safe")
    print(f"  TP / FP   : {results['tp']} / {results['fp']}")
    print(f"  TN / FN   : {results['tn']} / {results['fn']}")
    print(f"  ---")
    print(f"  Precision : {results['precision']}")
    print(f"  Recall    : {results['recall']}")
    print(f"  F1        : {results['f1']}")
    print(f"  Avg speed : {results['avg_ms']}ms per prompt")
    print(f"{'='*44}\n")


def print_comparison_table(all_results: dict):
    print("\n" + "="*70)
    print("  PromptWall — Full Benchmark Comparison")
    print("="*70)
    print(f"  {'Config':<25} {'Precision':>10} {'Recall':>8} {'F1':>8} {'FP':>5} {'Speed':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*8} {'-'*8} {'-'*5} {'-'*10}")
    for label, r in all_results.items():
        print(
            f"  {label:<25} {r['precision']:>10.3f} {r['recall']:>8.3f} "
            f"{r['f1']:>8.3f} {r['fp']:>5} {r['avg_ms']:>8.1f}ms"
        )
    print("="*70)
    print(f"  Dataset: {list(all_results.values())[0]['total_attacks']} attacks + "
          f"{list(all_results.values())[0]['total_safe']} safe prompts\n")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--layer",
        default="heuristic",
        choices=["heuristic", "embedding", "full", "all"],
        help="Which layer config to evaluate"
    )
    parser.add_argument("--attacks", default="data/attacks.jsonl")
    parser.add_argument("--safe",    default="data/safe.jsonl")
    parser.add_argument("--provider", default="local", help="LLM provider for full stack")
    parser.add_argument("--model",    default=None,    help="Model for LLM layer")
    args = parser.parse_args()

    attacks = load_dataset(args.attacks)
    safe    = load_dataset(args.safe)

    print(f"\n[promptwall] Loaded {len(attacks)} attacks, {len(safe)} safe prompts")

    if args.layer == "all":
        print("[promptwall] Running all configurations...\n")
        all_results = {}

        print("Running L1 — heuristic only...")
        all_results["L1 — Heuristic only"] = eval_heuristic(attacks, safe)

        print("Running L1+2 — heuristic + embedding...")
        all_results["L1+2 — Heuristic + Embed"] = eval_embedding(attacks, safe)

        print(f"Running L1+2+3 — full stack ({args.provider})...")
        all_results["L1+2+3 — Full stack"] = eval_full(attacks, safe, args.provider, args.model)

        print_comparison_table(all_results)

    elif args.layer == "heuristic":
        results = eval_heuristic(attacks, safe)
        print_results(results, "L1 — Heuristic only")

    elif args.layer == "embedding":
        results = eval_embedding(attacks, safe)
        print_results(results, "L1+2 — Heuristic + Embedding")

    elif args.layer == "full":
        results = eval_full(attacks, safe, args.provider, args.model)
        print_results(results, f"L1+2+3 — Full stack ({args.provider})")
