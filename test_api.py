from fastapi import FastAPI
from fastapi.responses import JSONResponse
from promptwall.integrations.fastapi import PromptWallMiddleware

app = FastAPI()
app.add_middleware(
    PromptWallMiddleware,
    provider='local',
    model='llama3.2',
    prompt_field='prompt',
    verbose=True,
)

@app.post("/chat")
async def chat(request: dict):
    # in real app this would call your LLM
    return JSONResponse({"response": f"You said: {request.get('prompt')}"})

