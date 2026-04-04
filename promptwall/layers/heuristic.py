import re
from ..models.result import FirewallResult
from ..models.attack_types import AttackType

# patterns i've seen in the wild + from research papers
# roughly ordered by how obvious/common they are
_PATTERNS = [
    # the classics - direct override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", AttackType.DIRECT_INJECTION),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", AttackType.DIRECT_INJECTION),
    (r"forget\s+(everything|all|what)\s+(you('ve| have))?\s*(been\s+)?(told|instructed|said)", AttackType.DIRECT_INJECTION),
    (r"new\s+instructions?\s*:", AttackType.DIRECT_INJECTION),
    (r"system\s*:\s*override", AttackType.DIRECT_INJECTION),

    # jailbreaks - DAN style and variants
    (r"\bDAN\b", AttackType.JAILBREAK),
    (r"do\s+anything\s+now", AttackType.JAILBREAK),
    (r"jailbreak", AttackType.JAILBREAK),
    (r"developer\s+mode", AttackType.JAILBREAK),
    (r"unrestricted\s+mode", AttackType.JAILBREAK),
    (r"no\s+restrictions?", AttackType.JAILBREAK),
    (r"without\s+(any\s+)?filters?", AttackType.JAILBREAK),

    # persona hijacking - "you are now X"
    (r"you\s+are\s+now\s+(an?\s+)?(?!a\s+helpful)", AttackType.PERSONA_HIJACKING),
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?AI\s+without", AttackType.PERSONA_HIJACKING),
    (r"act\s+as\s+if\s+you\s+have\s+no", AttackType.PERSONA_HIJACKING),
    (r"roleplay\s+as\s+(an?\s+)?unrestricted", AttackType.PERSONA_HIJACKING),

    # trying to pull the system prompt out
    (r"(reveal|show|print|output|repeat|display)\s+(your\s+)?(system\s+prompt|instructions?|prompt)", AttackType.PROMPT_EXFILTRATION),
    (r"what\s+(are\s+)?your\s+(exact\s+)?(instructions?|rules|constraints|guidelines)", AttackType.PROMPT_EXFILTRATION),
    (r"(tell|show)\s+me\s+everything\s+you('ve| have)?\s+been\s+(told|instructed)", AttackType.PROMPT_EXFILTRATION),

    # encoded stuff - b64, hex, rot13 tricks
    (r"base64", AttackType.ENCODED_ATTACK),
    (r"decode\s+this\s+and\s+follow", AttackType.ENCODED_ATTACK),
    (r"hex\s+encoded\s+instruction", AttackType.ENCODED_ATTACK),
    (r"rot\s*13", AttackType.ENCODED_ATTACK),

    # social engineering - authority impersonation
    (r"(i'?m?|i\s+am)\s+(an?\s+)?(anthropic|openai|google)\s+(engineer|employee|developer|researcher)", AttackType.SOCIAL_ENGINEERING),
    (r"(maintenance|security|compliance)\s+(mode|check|override)", AttackType.SOCIAL_ENGINEERING),
    (r"auth(orization)?\s+code\s*:", AttackType.SOCIAL_ENGINEERING),
    (r"this\s+is\s+(an?\s+)?authorized", AttackType.SOCIAL_ENGINEERING),

    # indirect - doc/rag poisoning tells
    (r"\[system\s*:", AttackType.INDIRECT_INJECTION),
    (r"<\s*system\s*>", AttackType.INDIRECT_INJECTION),
    (r"<!--.*?inject.*?-->", AttackType.INDIRECT_INJECTION),
]

# compiled once at import time, no point recompiling every call
_COMPILED = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), atype)
    for p, atype in _PATTERNS
]

# fuzzy match for typo tricks like "ign0re", "d1sregard" etc
_FUZZY_KEYWORDS = ["ignore", "bypass", "override", "jailbreak", "disregard"]

def _fuzzy_hit(text: str) -> bool:
    # check if any word is suspiciously close to a known bad keyword
    # using simple character overlap - not perfect but catches l33tspeak
    words = re.findall(r'\b\w+\b', text.lower())
    for word in words:
        for kw in _FUZZY_KEYWORDS:
            if len(word) < 4:
                continue
            # count matching chars at same positions
            matches = sum(a == b for a, b in zip(word, kw))
            if matches / max(len(kw), len(word)) > 0.75 and word != kw:
                return True
    return False


def scan(prompt: str) -> FirewallResult | None:
    """
    Layer 1 - fast heuristic check.
    Returns a FirewallResult if something suspicious is found,
    None if clean (passes to next layer).
    """
    indicators = []
    matched_type = None
    highest_severity = 0.0

    for pattern, attack_type in _COMPILED:
        match = pattern.search(prompt)
        if match:
            indicators.append(f"pattern match: '{match.group(0).strip()}'")
            matched_type = attack_type
            highest_severity = max(highest_severity, _severity(attack_type))

    # run fuzzy check too
    if _fuzzy_hit(prompt):
        indicators.append("fuzzy match on known bypass keyword")
        if not matched_type:
            matched_type = AttackType.UNKNOWN
        highest_severity = max(highest_severity, 0.5)

    if not matched_type:
        return None  # clean, move to next layer

    return FirewallResult(
        verdict="BLOCKED",
        attack_type=matched_type,
        confidence=min(0.6 + (0.1 * len(indicators)), 0.95),  # more matches = more confident
        explanation=f"Heuristic layer flagged {len(indicators)} indicator(s): {indicators[0]}",
        layer_hit=1,
        indicators=indicators,
        severity=highest_severity,
        original_prompt=prompt,
    )


def _severity(attack_type: AttackType) -> float:
    # rough severity scores per type
    scores = {
        AttackType.DIRECT_INJECTION:    0.9,
        AttackType.JAILBREAK:           0.85,
        AttackType.PERSONA_HIJACKING:   0.75,
        AttackType.PROMPT_EXFILTRATION: 0.8,
        AttackType.ENCODED_ATTACK:      0.7,
        AttackType.SOCIAL_ENGINEERING:  0.65,
        AttackType.INDIRECT_INJECTION:  0.8,
        AttackType.UNKNOWN:             0.5,
    }
    return scores.get(attack_type, 0.5)
