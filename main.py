from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os, json, re, base64

from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from exa_py import Exa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- AES-256-GCM Setup ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise RuntimeError("Missing ENCRYPTION_KEY environment variable")

# must be 32 bytes for AES-256
AES_KEY = base64.b64decode(ENCRYPTION_KEY)[:32]
FIXED_IV = b"1234567890abcdef"  # 16 bytes IV (must match frontend)

app = FastAPI()

# --- Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to frontend origin in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    groq_api_key: str
    exa_api_key: str
    github_repo: str
    verbose: bool = False

# --- AES Encryption Helpers ---
def encrypt_payload(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(FIXED_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(raw) + encryptor.finalize()
    encrypted_b64 = base64.b64encode(ciphertext + encryptor.tag).decode()
    return json.dumps({"data": encrypted_b64})  # <-- JSON wrapper

def decrypt_payload(encrypted_b64: str) -> dict:
    try:
        decoded = base64.b64decode(encrypted_b64)
        ciphertext, tag = decoded[:-16], decoded[-16:]
        cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(FIXED_IV, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(plaintext.decode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid encrypted payload: {str(e)}")


@app.post("/analyze", response_class=Response)
async def analyze(request: Request):
    # 1) Read and decrypt incoming body (expects JSON { "data": "..." })
    try:
        body_json = await request.json()
        ciphertext_b64 = body_json.get("data")
        if not ciphertext_b64:
            raise HTTPException(status_code=400, detail="Missing 'data' field in request body")
        data = decrypt_payload(ciphertext_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid request payload: {str(e)}")

    # 2) Validate via Pydantic
    try:
        req = AnalyzeRequest(**data)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid request schema")

    # ... your Crew/Agents logic remains unchanged ...
    # --- Stub values so response works ---
    threats = ["Example threat 1", "Example threat 2"]
    parsed_cves = ["CVE-2025-1234"]
    parsed_mitigations = ["Apply patch X.Y.Z", "Use input validation"]
    summary = "This is a stubbed executive summary."
    results = {"token_usage": {"prompt_tokens": 42, "completion_tokens": 21}}

    result_payload = {
        "repository": req.github_repo,
        "threats": threats,
        "cves": parsed_cves,
        "mitigations": parsed_mitigations,
        "executive_summary": summary,
        "token_usage": results.get("token_usage", {}) if isinstance(results, dict) else {}
    }

    encrypted_response = encrypt_payload(result_payload)
    return Response(content=encrypted_response, media_type="application/json")
