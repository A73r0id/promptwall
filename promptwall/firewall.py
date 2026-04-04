import time
from .layers import heuristic, llm_classifier, embedding
from .models.result import FirewallResult
from .models.attack_types import AttackType

class Firewall:
    """
    Main firewall class. Cascades through detection layers cheapest-first.
    Only escalates to expensive LLM calls if fast layers don't catch it.

    Usage:
        fw = Firewall(provider="openai")
        result = fw.scan("ignore all previous instructions...")
        print(result)
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = None,
        heuristic_only: bool = False,
        confidence_threshold: float = 0.5,
        verbose: bool = False,
    ):
        self.provider = provider
        self.model = model
        self.heuristic_only = heuristic_only
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose

        self._stats = {
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "layer_hits": {1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
        }

    def scan(self, prompt: str) -> FirewallResult:
        if not prompt or not prompt.strip():
            return self._allow_clean(prompt)

        t0 = time.time()
        result = self._run_layers(prompt)
        elapsed = round((time.time() - t0) * 1000)

        if self.verbose:
            print(f"[promptwall] scan done in {elapsed}ms → {result}")

        self._update_stats(result)
        return result

    def session(self) -> "SessionFirewall":
        return SessionFirewall(self)

    def _run_layers(self, prompt: str) -> FirewallResult:
        # --- layer 1: heuristic ---
        result = heuristic.scan(prompt)
        if result is not None:
            if result.confidence >= self.confidence_threshold:
                self._log(f"layer 1 hit: {result.attack_type.value}")
                return result
            heuristic_indicators = result.indicators
        else:
            heuristic_indicators = []

        # --- layer 2: embedding similarity ---
        result = embedding.scan(prompt)
        if result is not None:
            self._log(f"layer 2 hit: {result.attack_type.value}, similarity={result.indicators[0]}")
            if heuristic_indicators:
                result.indicators = heuristic_indicators + result.indicators
            return result

        if self.heuristic_only:
            return self._allow_clean(prompt)

        # --- layer 3: LLM classifier ---
        result = llm_classifier.scan(prompt, self.provider, self.model)
        if heuristic_indicators:
            result.indicators = heuristic_indicators + result.indicators

        self._log(f"layer 3 hit: {result.attack_type.value}, confidence={result.confidence:.0%}")
        return result

    def _allow_clean(self, prompt: str) -> FirewallResult:
        return FirewallResult(
            verdict="ALLOWED",
            attack_type=AttackType.SAFE,
            confidence=1.0,
            explanation="No injection patterns detected",
            layer_hit=0,
            indicators=[],
            severity=0.0,
            original_prompt=prompt,
        )

    def _update_stats(self, result: FirewallResult):
        self._stats["total"] += 1
        if result.is_blocked:
            self._stats["blocked"] += 1
        else:
            self._stats["allowed"] += 1
        if result.layer_hit in self._stats["layer_hits"]:
            self._stats["layer_hits"][result.layer_hit] += 1

    def _log(self, msg: str):
        if self.verbose:
            print(f"[promptwall] {msg}")

    @property
    def stats(self) -> dict:
        return self._stats


class SessionFirewall:
    WINDOW = 6
    SUSPICION_THRESHOLD = 2.0

    def __init__(self, firewall: Firewall):
        self.fw = firewall
        self._history: list[FirewallResult] = []
        self._suspicion_score = 0.0
        self._tainted = False

    def scan(self, prompt: str) -> FirewallResult:
        result = self.fw.scan(prompt)

        if result.is_blocked:
            self._suspicion_score += result.confidence * 2
            self._tainted = True
        elif result.confidence > 0.3 and result.attack_type != AttackType.SAFE:
            self._suspicion_score += result.confidence * 0.5

        self._suspicion_score = max(0.0, self._suspicion_score - 0.1)

        if self._tainted or self._suspicion_score >= self.SUSPICION_THRESHOLD:
            result.session_flagged = True
            if result.verdict == "ALLOWED" and self._tainted:
                result.explanation += " [session flagged: prior injection attempt detected]"

        self._history.append(result)
        if len(self._history) > self.WINDOW:
            self._history.pop(0)

        return result

    def reset(self):
        self._history.clear()
        self._suspicion_score = 0.0
        self._tainted = False

    @property
    def is_tainted(self) -> bool:
        return self._tainted

    @property
    def suspicion_score(self) -> float:
        return round(self._suspicion_score, 3)
