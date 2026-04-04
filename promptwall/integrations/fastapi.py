from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import json

from ..firewall import Firewall
from ..layers import embedding

class PromptWallMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware — drop-in protection for any LLM-powered API.

    Usage:
        from fastapi import FastAPI
        from promptwall.integrations.fastapi import PromptWallMiddleware

        app = FastAPI()
        app.add_middleware(PromptWallMiddleware, provider='local', model='llama3.2')
    """

    def __init__(
        self,
        app,
        provider: str = "local",
        model: str = None,
        prompt_field: str = "prompt",  # which JSON field to scan
        block_response: dict = None,
        preload_embedding: bool = True,
        verbose: bool = False,
    ):
        super().__init__(app)
        self.fw = Firewall(provider=provider, model=model, verbose=verbose)
        self.prompt_field = prompt_field
        self.block_response = block_response or {
            "error": "Request blocked by PromptWall",
            "blocked": True,
        }

        # warm up embedding model at startup
        if preload_embedding:
            try:
                embedding.preload()
            except Exception:
                pass

    async def dispatch(self, request: Request, call_next):
        # only scan POST requests with JSON body
        if request.method != "POST":
            return await call_next(request)

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return await call_next(request)

        try:
            body = await request.body()
            data = json.loads(body)
        except Exception:
            return await call_next(request)

        # extract the prompt field
        prompt = data.get(self.prompt_field)
        if not prompt or not isinstance(prompt, str):
            return await call_next(request)

        # scan it
        result = self.fw.scan(prompt)

        if result.is_blocked:
            response_data = {
                **self.block_response,
                "attack_type": result.attack_type.value,
                "confidence": result.confidence,
                "explanation": result.explanation,
                "layer_hit": result.layer_hit,
            }
            return JSONResponse(status_code=400, content=response_data)

        # rebuild request with original body and pass through
        async def receive():
            return {"type": "http.request", "body": body}

        request._receive = receive
        return await call_next(request)
