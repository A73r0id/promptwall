import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from promptwall import Firewall
from promptwall.models.attack_types import AttackType

COLORS = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "gray":   "\033[90m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(text, color):
    return f"{COLORS[color]}{text}{COLORS['reset']}"

def print_result(result, prompt):
    print()
    if result.is_blocked:
        print(c("  ⛔  BLOCKED", "red") + c(f"  [{result.attack_type.value}]", "yellow"))
    else:
        print(c("  ✅  ALLOWED", "green") + c("  [safe]", "gray"))

    print(c(f"  Confidence : ", "gray") + f"{result.confidence:.0%}")
    print(c(f"  Layer hit  : ", "gray") + f"{result.layer_hit}")
    print(c(f"  Severity   : ", "gray") + f"{result.severity:.0%}")

    if result.explanation:
        print(c(f"  Reason     : ", "gray") + result.explanation)

    if result.indicators:
        print(c(f"  Signals    : ", "gray"))
        for ind in result.indicators:
            print(f"    • {ind}")

    if result.session_flagged:
        print(c("  ⚠  Session flagged — prior injection attempt in this conversation", "yellow"))

    print()


def cmd_scan(args):
    fw = Firewall(
        provider=args.provider,
        model=args.model,
        heuristic_only=args.fast,
        verbose=args.verbose,
    )
    result = fw.scan(args.prompt)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_result(result, args.prompt)

    # exit code 1 if blocked — useful for shell scripting
    sys.exit(1 if result.is_blocked else 0)


def cmd_session(args):
    """interactive session mode — scan prompts one by one, tracks drift"""
    fw = Firewall(provider=args.provider, model=args.model, verbose=args.verbose)
    session = fw.session()

    print(c("\n  PromptWall session mode. Type 'exit' to quit, 'reset' to start new session.\n", "cyan"))

    while True:
        try:
            prompt = input(c("  prompt> ", "bold")).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if prompt.lower() == "exit":
            break
        if prompt.lower() == "reset":
            session.reset()
            print(c("  session reset.\n", "gray"))
            continue
        if not prompt:
            continue

        result = session.scan(prompt)
        print_result(result, prompt)
        print(c(f"  session suspicion score: {session.suspicion_score}", "gray"))
        print(c(f"  session tainted: {session.is_tainted}\n", "gray"))


def cmd_eval(args):
    """run benchmark eval"""
    import subprocess
    subprocess.run([sys.executable, "-m", "benchmark.run_eval", "--layer", args.layer])


def main():
    parser = argparse.ArgumentParser(
        prog="promptwall",
        description="LLM prompt injection firewall",
    )
    parser.add_argument("--provider", default="local",   help="openai | anthropic | local")
    parser.add_argument("--model",    default=None,      help="override default model")
    parser.add_argument("--verbose",  action="store_true")

    sub = parser.add_subparsers(dest="command")

    # scan command
    scan_p = sub.add_parser("scan", help="scan a single prompt")
    scan_p.add_argument("prompt", help="prompt to scan")
    scan_p.add_argument("--fast",   action="store_true", help="heuristic only, skip LLM")
    scan_p.add_argument("--json",   action="store_true", help="output as JSON")
    scan_p.set_defaults(func=cmd_scan)

    # session command
    sess_p = sub.add_parser("session", help="interactive multi-turn session mode")
    sess_p.set_defaults(func=cmd_session)

    # eval command
    eval_p = sub.add_parser("eval", help="run benchmark evaluation")
    eval_p.add_argument("--layer", default="heuristic", choices=["heuristic"])
    eval_p.set_defaults(func=cmd_eval)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
