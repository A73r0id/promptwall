# layer 4 - standalone session tracking utilities
# SessionFirewall in firewall.py handles the main logic
# this module has helpers for drift scoring if needed externally

def compute_drift_score(results: list) -> float:
    """
    given a list of FirewallResults from a session,
    returns a drift score 0-1 indicating how much
    the intent has shifted toward malicious over time
    """
    if not results:
        return 0.0
    total = sum(r.confidence for r in results if r.is_blocked)
    return min(total / max(len(results), 1), 1.0)


def is_escalating(results: list) -> bool:
    """check if confidence scores are trending upward - sign of a probing attack"""
    if len(results) < 3:
        return False
    scores = [r.confidence for r in results[-3:]]
    return scores[2] > scores[1] > scores[0]
