from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os, json, re, base64
from typing import List, Dict, Any, Optional

from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from exa_py import Exa

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()

# --- Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to explicit origin(s) for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- AES-GCM constants ----------
AAD_CONTEXT_DEFAULT = b"analyze-v1"  # associated data
IV_CONST = b"\x00" * 12              # 96-bit static IV (for demo only, insecure in prod!)
TAG_CONST = b"\x00" * 16             # static tag placeholder (for demo only)

# ---------- Payload models ----------
class EncryptedPayload(BaseModel):
    ciphertext: str   # base64 encoded ciphertext only
    aad: Optional[str] = None

# ---------- AES-GCM helpers ----------
def _get_aes_key() -> bytes:
    key_env = os.getenv("AES_GCM_KEY")
    if not key_env:
        raise HTTPException(status_code=500, detail="AES_GCM_KEY not set on server")
    # Try base64
    try:
        k = base64.b64decode(key_env)
        if len(k) == 32:
            return k
    except Exception:
        pass
    # Try hex
    try:
        k = bytes.fromhex(key_env)
        if len(k) == 32:
            return k
    except Exception:
        pass
    raise HTTPException(status_code=500, detail="AES_GCM_KEY must be 32 bytes (Base64 or hex)")

def encrypt_json(obj: Any, aad: Optional[bytes] = None) -> Dict[str, str]:
    key = _get_aes_key()
    aes = AESGCM(key)
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if aad is None:
        aad = AAD_CONTEXT_DEFAULT
    # Encrypt using fixed IV
    c_and_tag = aes.encrypt(IV_CONST, plaintext, aad)
    ciphertext, tag = c_and_tag[:-16], c_and_tag[-16:]
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "aad": (aad.decode() if isinstance(aad, bytes) else aad),
    }

def decrypt_to_json(payload: EncryptedPayload) -> Any:
    key = _get_aes_key()
    aes = AESGCM(key)
    try:
        ct = base64.b64decode(payload.ciphertext)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in encrypted payload")
    # Append tag constant
    c_and_tag = ct + TAG_CONST
    aad = (payload.aad.encode() if isinstance(payload.aad, str) else AAD_CONTEXT_DEFAULT)
    try:
        plaintext = aes.decrypt(IV_CONST, c_and_tag, aad)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Decrypted data is not valid JSON")

# ---------- Your existing AnalyzeRequest and /analyze endpoint ----------
class AnalyzeRequest(BaseModel):
    groq_api_key: str
    exa_api_key: str
    github_repo: str
    verbose: bool = False

# (KEEP your existing /analyze function here unchanged)

# ---------- New encrypted endpoint ----------
@app.post("/analyze_secure")
def analyze_secure(payload: EncryptedPayload):
    """
    Accepts AES-256-GCM encrypted request with only 'ciphertext' (server uses static IV/TAG),
    returns AES-256-GCM encrypted response.
    """
    # Decrypt request -> dict
    inner = decrypt_to_json(payload)

    # Validate into AnalyzeRequest
    try:
        req = AnalyzeRequest(**inner)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid AnalyzeRequest fields: {e}")

    # Run the existing analyze function directly (calls the same logic)
    result = analyze(req)  # returns dict or raises

    # Encrypt response (ciphertext only, using static IV/TAG)
    aad_bytes = (payload.aad.encode() if isinstance(payload.aad, str) else AAD_CONTEXT_DEFAULT)
    enc = encrypt_json(result, aad=aad_bytes)
    return enc
