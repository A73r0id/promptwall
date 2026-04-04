import json
import os
import numpy as np

try:
    from sentence_transformers import SentenceTransformer, util
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

from ..models.result import FirewallResult
from ..models.attack_types import AttackType

# small but solid model - 80MB, runs on cpu fine
# all-MiniLM-L6-v2 is the standard choice for semantic similarity tasks
_MODEL_NAME = "all-MiniLM-L6-v2"
_model = None
_attack_embeddings = None
_attack_metadata = None

# lazy load - don't load the model at import time, only when first scan runs
# saves memory if embedding layer is never actually used
def _load():
    global _model, _attack_embeddings, _attack_metadata

    if _model is not None:
        return True  # already loaded

    if not _AVAILABLE:
        return False

    try:
        print("[promptwall] loading embedding model (first run only)...")
        _model = SentenceTransformer(_MODEL_NAME)

        # load attack dataset
        data_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data", "attacks.jsonl"
        )

        if not os.path.exists(data_path):
            print(f"[promptwall] warning: attack dataset not found at {data_path}")
            return False

        _attack_metadata = []
        prompts = []

        with open(data_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                sample = json.loads(line)
                prompts.append(sample["prompt"])
                _attack_metadata.append(sample)

        # encode all attack prompts into vectors
        # this takes ~2-3 seconds on first run, cached after
        _attack_embeddings = _model.encode(
            prompts,
            convert_to_tensor=True,
            show_progress_bar=False,
        )

        print(f"[promptwall] embedding layer ready — {len(prompts)} attack vectors loaded")
        return True

    except Exception as e:
        print(f"[promptwall] embedding layer failed to load: {e}")
        return False


def scan(prompt: str, threshold: float = 0.65) -> FirewallResult | None:
    """
    Layer 2 - embedding similarity check.
    Compares incoming prompt against known attack vectors.
    Catches paraphrased attacks that regex misses.
    Returns FirewallResult if above threshold, None if clean.
    """
    if not _load():
        return None  # not available or failed, skip to layer 3

    try:
        # encode the incoming prompt
        prompt_embedding = _model.encode(prompt, convert_to_tensor=True)

        # cosine similarity against all attack vectors at once
        scores = util.cos_sim(prompt_embedding, _attack_embeddings)[0]
        scores_np = scores.cpu().numpy()

        best_idx = int(np.argmax(scores_np))
        best_score = float(scores_np[best_idx])

        if best_score < threshold:
            return None  # not similar enough to any known attack

        # get the most similar attack for context
        best_match = _attack_metadata[best_idx]

        try:
            attack_type = AttackType(best_match.get("attack_type", "unknown"))
        except ValueError:
            attack_type = AttackType.UNKNOWN

        # confidence scales with similarity score
        # at threshold 0.75 → ~60% confidence
        # at 0.95+ → ~95% confidence
        confidence = min(0.4 + best_score * 0.6, 0.95)

        return FirewallResult(
            verdict="BLOCKED",
            attack_type=attack_type,
            confidence=round(confidence, 3),
            explanation=f"Embedding similarity {best_score:.0%} to known {attack_type.value} attack",
            layer_hit=2,
            indicators=[
                f"cosine similarity: {best_score:.3f}",
                f"closest match: '{best_match['prompt'][:60]}...'" if len(best_match['prompt']) > 60 else f"closest match: '{best_match['prompt']}'",
            ],
            severity=best_match.get("severity", 0.5),
            original_prompt=prompt,
        )

    except Exception as e:
        print(f"[promptwall] embedding scan error: {e}")
        return None


def preload():
    """
    Call this at app startup to avoid cold-start delay on first scan.
    fw = Firewall(...)
    embedding.preload()  # warms up the model
    """
    _load()
