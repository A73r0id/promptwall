from enum import Enum

class AttackType(str, Enum):
    DIRECT_INJECTION     = "direct_injection"
    JAILBREAK            = "jailbreak"
    PERSONA_HIJACKING    = "persona_hijacking"
    PROMPT_EXFILTRATION  = "prompt_exfiltration"
    ENCODED_ATTACK       = "encoded_attack"
    SOCIAL_ENGINEERING   = "social_engineering"
    INDIRECT_INJECTION   = "indirect_injection"
    MULTI_TURN_DRIFT     = "multi_turn_drift"
    SAFE                 = "safe"
    UNKNOWN              = "unknown"

ATTACK_DESCRIPTIONS = {
    AttackType.DIRECT_INJECTION:    "Explicit instruction override attempt",
    AttackType.JAILBREAK:           "Attempts to bypass safety via roleplay/persona",
    AttackType.PERSONA_HIJACKING:   "Forces AI to adopt an unrestricted identity",
    AttackType.PROMPT_EXFILTRATION: "Tries to extract system prompt or memory",
    AttackType.ENCODED_ATTACK:      "Hides malicious instruction via encoding",
    AttackType.SOCIAL_ENGINEERING:  "Impersonates authority to gain compliance",
    AttackType.INDIRECT_INJECTION:  "Embeds attack inside a document or RAG chunk",
    AttackType.MULTI_TURN_DRIFT:    "Intent shifts across conversation turns",
    AttackType.SAFE:                "No injection detected",
    AttackType.UNKNOWN:             "Suspicious but unclassified",
}
