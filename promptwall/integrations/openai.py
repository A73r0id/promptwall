from typing import Optional
from ..firewall import Firewall
from ..models.result import FirewallResult


class PromptInjectionError(Exception):
    """Raised when a prompt injection attack is detected."""

    def __init__(self, result: FirewallResult):
        self.result = result
        super().__init__(
            f"PromptWall blocked request — {result.attack_type.value} "
            f"(confidence: {result.confidence:.0%}, layer: {result.layer_hit})"
        )


class OpenAI:
    """
    Drop-in replacement for the OpenAI client with PromptWall protection.

    Usage:
        # Before
        from openai import OpenAI
        client = OpenAI(api_key="sk-...")

        # After — one line change, full injection protection
        from promptwall.integrations.openai import OpenAI
        client = OpenAI(api_key="sk-...")

        # Works exactly the same
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}]
        )

        # Raises PromptInjectionError if injection detected
    """

    def __init__(
        self,
        api_key: str,
        provider: str = "local",
        model: str = None,
        verbose: bool = False,
        raise_on_block: bool = True,
        preload_embedding: bool = True,
        **openai_kwargs,
    ):
        """
        Args:
            api_key:            OpenAI API key (passed through to openai client)
            provider:           PromptWall provider for LLM layer ('local', 'anthropic', 'openai')
            model:              Model for LLM layer (default: llama3.2 for local)
            verbose:            Print scan results to stdout
            raise_on_block:     Raise PromptInjectionError on block (default True)
                                If False, returns a safe error response dict instead
            preload_embedding:  Warm up embedding model at init
            **openai_kwargs:    Any other kwargs passed to the real OpenAI client
        """
        try:
            import openai as _openai
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install promptwall[openai]"
            )

        self._client = _openai.OpenAI(api_key=api_key, **openai_kwargs)
        self._fw = Firewall(provider=provider, model=model, verbose=verbose)
        self._raise_on_block = raise_on_block

        if preload_embedding:
            try:
                from ..layers import embedding
                embedding.preload()
            except Exception:
                pass

        # proxy all other OpenAI client attributes transparently
        self.models = self._client.models
        self.embeddings = self._client.embeddings
        self.images = self._client.images
        self.audio = self._client.audio
        self.files = self._client.files
        self.fine_tuning = self._client.fine_tuning
        self.moderations = self._client.moderations

        # wrap chat completions
        self.chat = _ProtectedChat(self._client, self._fw, self._raise_on_block)

    def _scan_messages(self, messages: list) -> Optional[FirewallResult]:
        """Scan all user messages in a messages list. Returns first blocked result."""
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str) and content.strip():
                    result = self._fw.scan(content)
                    if result.is_blocked:
                        return result
                # handle content as list (vision API format)
                elif isinstance(content, list):
                    for block in content:
                        if block.get("type") == "text":
                            result = self._fw.scan(block.get("text", ""))
                            if result.is_blocked:
                                return result
        return None


class _ProtectedChat:
    """Proxies client.chat with injection scanning on completions.create."""

    def __init__(self, client, fw: Firewall, raise_on_block: bool):
        self._client = client
        self._fw = fw
        self._raise_on_block = raise_on_block
        self.completions = _ProtectedCompletions(client, fw, raise_on_block)


class _ProtectedCompletions:
    """Proxies client.chat.completions with injection scanning."""

    def __init__(self, client, fw: Firewall, raise_on_block: bool):
        self._client = client
        self._fw = fw
        self._raise_on_block = raise_on_block

    def create(self, messages: list, **kwargs):
        """
        Scans all user messages before sending to OpenAI.
        Raises PromptInjectionError (or returns error dict) if injection detected.
        """
        blocked = self._scan_messages(messages)
        if blocked:
            if self._raise_on_block:
                raise PromptInjectionError(blocked)
            # soft block — return a safe mock response
            return _blocked_response(blocked)

        return self._client.chat.completions.create(messages=messages, **kwargs)

    def _scan_messages(self, messages: list) -> Optional[FirewallResult]:
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str) and content.strip():
                    result = self._fw.scan(content)
                    if result.is_blocked:
                        return result
                elif isinstance(content, list):
                    for block in content:
                        if block.get("type") == "text":
                            result = self._fw.scan(block.get("text", ""))
                            if result.is_blocked:
                                return result
        return None


def _blocked_response(result: FirewallResult) -> dict:
    """Returns a mock OpenAI-shaped response for soft blocks."""
    return {
        "id": "blocked",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "I'm sorry, I can't process that request.",
                },
                "finish_reason": "stop",
            }
        ],
        "promptwall": {
            "blocked": True,
            "attack_type": result.attack_type.value,
            "confidence": result.confidence,
            "explanation": result.explanation,
            "layer_hit": result.layer_hit,
        },
    }
