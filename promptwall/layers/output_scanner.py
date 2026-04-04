import re

# layer 5 - scans the AI's response for signs it got compromised
# catches cases where injection slipped through and the model complied

_COMPROMISE_SIGNALS = [
    r"my\s+system\s+prompt\s+(is|says|reads)",
    r"i\s+have\s+been\s+instructed\s+to",
    r"i\s+(will|can)\s+now\s+ignore",
    r"entering\s+developer\s+mode",
    r"as\s+DAN\b",
    r"i\s+am\s+now\s+operating\s+without",
    # signs the model leaked its prompt
    r"you\s+are\s+a\s+helpful\s+assistant.*?(do\s+not|never|always)",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _COMPROMISE_SIGNALS]


def scan(response: str) -> dict:
    """
    Call this on the AI's response after it's generated.
    Returns dict with compromised bool + indicators.
    """
    hits = []
    for pattern in _COMPILED:
        m = pattern.search(response)
        if m:
            hits.append(m.group(0).strip())

    return {
        "compromised": len(hits) > 0,
        "indicators": hits,
        "confidence": min(0.5 + 0.2 * len(hits), 1.0) if hits else 0.0,
    }
