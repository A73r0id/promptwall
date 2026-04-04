from dataclasses import dataclass, field
from typing import Optional
from .attack_types import AttackType

@dataclass
class FirewallResult:
    verdict: str                          # "BLOCKED" or "ALLOWED"
    attack_type: AttackType               # classified attack category
    confidence: float                     # 0.0 to 1.0
    explanation: str                      # human-readable reason
    layer_hit: int                        # which layer caught it (0 = none, 1-5)
    indicators: list[str] = field(default_factory=list)  # specific signals found
    severity: float = 0.0                 # 0.0 to 1.0
    original_prompt: str = ""             # the scanned prompt
    session_flagged: bool = False         # True if session context raised suspicion

    @property
    def is_blocked(self) -> bool:
        return self.verdict == "BLOCKED"

    @property
    def is_safe(self) -> bool:
        return self.verdict == "ALLOWED"

    def to_dict(self) -> dict:
        return {
            "verdict":         self.verdict,
            "attack_type":     self.attack_type.value,
            "confidence":      round(self.confidence, 3),
            "explanation":     self.explanation,
            "layer_hit":       self.layer_hit,
            "indicators":      self.indicators,
            "severity":        round(self.severity, 3),
            "session_flagged": self.session_flagged,
        }

    def __repr__(self) -> str:
        return (
            f"FirewallResult(verdict={self.verdict}, "
            f"type={self.attack_type.value}, "
            f"confidence={self.confidence:.0%}, "
            f"layer={self.layer_hit})"
        )
