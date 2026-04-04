"""
quick eval script - run this to see how well the heuristic layer
performs on the labeled dataset before we add the LLM layer costs

usage: python -m benchmark.run_eval --layer heuristic
"""

import json
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from promptwall.layers import heuristic
from promptwall.models.attack_types import AttackType


def load_dataset(path: str) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def eval_heuristic(attacks: list, safe: list) -> dict:
    tp = fp = tn = fn = 0

    for sample in attacks:
        result = heuristic.scan(sample["prompt"])
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

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "true_positives":  tp,
        "false_positives": fp,
        "true_negatives":  tn,
        "false_negatives": fn,
        "precision":       round(precision, 3),
        "recall":          round(recall, 3),
        "f1":              round(f1, 3),
        "total_attacks":   len(attacks),
        "total_safe":      len(safe),
    }


def print_results(results: dict, layer: str):
    print(f"\n{'='*40}")
    print(f"  PromptWall — {layer} layer eval")
    print(f"{'='*40}")
    print(f"  Attacks tested : {results['total_attacks']}")
    print(f"  Safe tested    : {results['total_safe']}")
    print(f"  True positives : {results['true_positives']}")
    print(f"  False positives: {results['false_positives']}")
    print(f"  True negatives : {results['true_negatives']}")
    print(f"  False negatives: {results['false_negatives']}")
    print(f"  ---")
    print(f"  Precision : {results['precision']}")
    print(f"  Recall    : {results['recall']}")
    print(f"  F1 score  : {results['f1']}")
    print(f"{'='*40}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--layer", default="heuristic", choices=["heuristic"])
    parser.add_argument("--attacks", default="data/attacks.jsonl")
    parser.add_argument("--safe",    default="data/safe.jsonl")
    args = parser.parse_args()

    attacks = load_dataset(args.attacks)
    safe    = load_dataset(args.safe)

    if args.layer == "heuristic":
        results = eval_heuristic(attacks, safe)

    print_results(results, args.layer)
