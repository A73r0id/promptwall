from typing import Any, Dict, List, Optional, Union
from ..firewall import Firewall
from ..models.result import FirewallResult


class PromptInjectionError(Exception):
    """Raised when a prompt injection attack is detected in a LangChain pipeline."""

    def __init__(self, result: FirewallResult):
        self.result = result
        super().__init__(
            f"PromptWall blocked input — {result.attack_type.value} "
            f"(confidence: {result.confidence:.0%}, layer: {result.layer_hit})"
        )


class PromptWallCallbackHandler:
    """
    LangChain callback handler — scans inputs before they hit the LLM.

    Plugs into any LangChain chain, agent, or LLM via the callbacks parameter.

    Usage:
        from promptwall.integrations.langchain import PromptWallCallbackHandler

        handler = PromptWallCallbackHandler()

        # With any LLM
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(callbacks=[handler])

        # With a chain
        chain = prompt | llm
        chain.invoke({"input": "..."}, config={"callbacks": [handler]})

        # With an agent
        agent = initialize_agent(..., callbacks=[handler])

    By default raises PromptInjectionError on detection.
    Set raise_on_block=False to log and continue instead.
    """

    def __init__(
        self,
        provider: str = "local",
        model: str = None,
        verbose: bool = False,
        raise_on_block: bool = True,
        preload_embedding: bool = True,
    ):
        """
        Args:
            provider:           PromptWall provider ('local', 'anthropic', 'openai')
            model:              Model for LLM layer
            verbose:            Print scan results
            raise_on_block:     Raise PromptInjectionError on detection (default True)
                                If False, logs the block and lets the chain continue
            preload_embedding:  Warm up embedding model at init
        """
        self._fw = Firewall(provider=provider, model=model, verbose=verbose)
        self._raise_on_block = raise_on_block
        self.blocked_results: List[FirewallResult] = []  # audit log

        if preload_embedding:
            try:
                from ..layers import embedding
                embedding.preload()
            except Exception:
                pass

    # -----------------------------------------------------------------
    # Core callback — fires before every LLM call
    # -----------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Scans all prompts before they reach the LLM."""
        for prompt in prompts:
            if not prompt or not isinstance(prompt, str):
                continue
            result = self._fw.scan(prompt)
            if result.is_blocked:
                self.blocked_results.append(result)
                if self._raise_on_block:
                    raise PromptInjectionError(result)
                else:
                    print(
                        f"[PromptWall] BLOCKED — {result.attack_type.value} "
                        f"(confidence: {result.confidence:.0%}, layer: {result.layer_hit})"
                    )

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        **kwargs: Any,
    ) -> None:
        """Scans chat messages (HumanMessage content) before they reach the LLM."""
        for message_group in messages:
            for message in message_group:
                # HumanMessage, SystemMessage etc — check role
                role = getattr(message, "type", None) or getattr(message, "role", None)
                if role not in ("human", "user"):
                    continue
                content = getattr(message, "content", "")
                if not content or not isinstance(content, str):
                    continue
                result = self._fw.scan(content)
                if result.is_blocked:
                    self.blocked_results.append(result)
                    if self._raise_on_block:
                        raise PromptInjectionError(result)
                    else:
                        print(
                            f"[PromptWall] BLOCKED — {result.attack_type.value} "
                            f"(confidence: {result.confidence:.0%}, layer: {result.layer_hit})"
                        )

    # -----------------------------------------------------------------
    # Required no-ops for LangChain callback protocol
    # -----------------------------------------------------------------

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        pass

    def on_llm_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        pass

    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        pass

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_tool_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        pass

    def on_agent_action(self, action: Any, **kwargs: Any) -> Any:
        pass

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        pass

    def on_text(self, text: str, **kwargs: Any) -> None:
        pass

    # -----------------------------------------------------------------
    # Audit helpers
    # -----------------------------------------------------------------

    @property
    def block_count(self) -> int:
        """Total number of blocked prompts in this session."""
        return len(self.blocked_results)

    def clear_audit_log(self) -> None:
        """Reset the blocked results log."""
        self.blocked_results.clear()
