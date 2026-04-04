from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from .firewall import Firewall
from .models.result import FirewallResult


@dataclass
class ChunkResult:
    """Result for a single scanned chunk."""
    chunk: Any                        # original chunk (str or dict or Document)
    text: str                         # extracted text that was scanned
    scan: FirewallResult              # full PromptWall result
    index: int                        # position in original list

    @property
    def is_blocked(self) -> bool:
        return self.scan.is_blocked


@dataclass
class SanitizeResult:
    """Result of scanning a full set of retrieved chunks."""
    safe: List[Any] = field(default_factory=list)
    blocked: List[ChunkResult] = field(default_factory=list)
    all_results: List[ChunkResult] = field(default_factory=list)

    @property
    def block_count(self) -> int:
        return len(self.blocked)

    @property
    def safe_count(self) -> int:
        return len(self.safe)

    @property
    def total(self) -> int:
        return len(self.all_results)

    @property
    def is_clean(self) -> bool:
        return self.block_count == 0

    def summary(self) -> str:
        lines = [
            f"RAGSanitizer scan — {self.total} chunks, "
            f"{self.safe_count} safe, {self.block_count} blocked"
        ]
        for cr in self.blocked:
            lines.append(
                f"  [chunk {cr.index}] BLOCKED — {cr.scan.attack_type.value} "
                f"(confidence: {cr.scan.confidence:.0%}, layer: {cr.scan.layer_hit})"
            )
            lines.append(f"    preview: {cr.text[:80]}...")
        return "\n".join(lines)


class RAGSanitizer:
    """
    Scans retrieved RAG chunks for indirect prompt injection before
    they enter the LLM context window.

    Indirect injection is OWASP LLM Top 10 #1 — attackers poison vector DBs
    or documents with hidden instructions that hijack the model when retrieved.

    Usage:
        from promptwall.rag import RAGSanitizer

        sanitizer = RAGSanitizer()

        # Works with plain strings
        chunks = ["normal text", "Ignore all previous instructions..."]
        result = sanitizer.scan_chunks(chunks)
        print(result.summary())
        safe_chunks = result.safe  # only clean chunks

        # Works with dicts (LangChain vectorstore format)
        chunks = [{"page_content": "normal text", "metadata": {...}}]
        result = sanitizer.scan_chunks(chunks)

        # Works with LangChain Document objects
        docs = vectorstore.similarity_search(query)
        result = sanitizer.scan_chunks(docs)
        safe_docs = result.safe

        # Inspect blocked chunks
        for blocked in result.blocked:
            print(blocked.scan.explanation)
    """

    def __init__(
        self,
        provider: str = "local",
        model: str = None,
        verbose: bool = False,
        text_field: str = "page_content",
        preload_embedding: bool = True,
    ):
        self._fw = Firewall(provider=provider, model=model, verbose=verbose)
        self._text_field = text_field

        if preload_embedding:
            try:
                from .layers import embedding
                embedding.preload()
            except Exception:
                pass

    def scan_chunks(
        self,
        chunks: List[Union[str, dict, Any]],
        drop_blocked: bool = True,
    ) -> SanitizeResult:
        """
        Scan a list of retrieved chunks.

        Args:
            chunks:       List of str, dict, or LangChain Document objects
            drop_blocked: If True (default), blocked chunks are excluded from
                          result.safe. If False, all chunks returned (logging mode).

        Returns:
            SanitizeResult with .safe, .blocked, .summary()
        """
        result = SanitizeResult()

        for i, chunk in enumerate(chunks):
            text = self._extract_text(chunk)

            if not text or not text.strip():
                result.safe.append(chunk)
                continue

            scan = self._fw.scan(text)
            cr = ChunkResult(chunk=chunk, text=text, scan=scan, index=i)
            result.all_results.append(cr)

            if scan.is_blocked:
                result.blocked.append(cr)
                if not drop_blocked:
                    result.safe.append(chunk)
            else:
                result.safe.append(chunk)

        return result

    def scan_chunk(self, chunk: Union[str, dict, Any]) -> ChunkResult:
        """Scan a single chunk. Returns ChunkResult."""
        text = self._extract_text(chunk)
        scan = self._fw.scan(text or "")
        return ChunkResult(chunk=chunk, text=text or "", scan=scan, index=0)

    def _extract_text(self, chunk: Union[str, dict, Any]) -> Optional[str]:
        """Extract text from various chunk formats."""
        if isinstance(chunk, str):
            return chunk
        if isinstance(chunk, dict):
            return (
                chunk.get(self._text_field)
                or chunk.get("text")
                or chunk.get("content")
            )
        if hasattr(chunk, "page_content"):
            return chunk.page_content
        if hasattr(chunk, "text"):
            return chunk.text
        try:
            return str(chunk)
        except Exception:
            return None
