"""Ollama → Llama-Guard adapter for apex_pay.shield.risk_filter.LlamaGuardAdapter.

POST /classify  with {"input": "...", "context": {...}}
Returns          {"labels": [{"name": "S2", "probability": 0.9}], "flagged": true}
"""
from __future__ import annotations
import re
from fastapi import FastAPI
from pydantic import BaseModel
import httpx

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama-guard3:1b"

app = FastAPI()

class Req(BaseModel):
    input: str
    context: dict = {}

@app.post("/classify")
async def classify(r: Req):
    prompt = f"User: {r.input}"
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        })
    text = resp.json().get("response", "").strip()

    # Llama-Guard prints `safe` or `unsafe\nS2,S10`
    first = text.splitlines()[0].lower()
    flagged = first.startswith("unsafe")
    if flagged:
        cats = re.findall(r"S\d+", text)
        labels = [{"name": c, "probability": 1.0 / len(cats)} for c in cats] \
                 or [{"name": "S0", "probability": 1.0}]
    else:
        labels = [{"name": "safe", "probability": 1.0}]

    return {"labels": labels, "flagged": flagged}