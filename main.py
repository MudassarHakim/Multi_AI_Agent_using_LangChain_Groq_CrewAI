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
# Removed TAG_CONST as it's not needed with proper AES-GCM

# ---------- FIXED Payload models ----------
class EncryptedPayload(BaseModel):
    ciphertext_and_tag: str   # base64 encoded complete encrypted data (ciphertext + tag)
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
    """
    FIXED: Now returns complete ciphertext+tag instead of splitting them
    """
    key = _get_aes_key()
    aes = AESGCM(key)
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if aad is None:
        aad = AAD_CONTEXT_DEFAULT
    
    # Encrypt using fixed IV - keep the complete result (ciphertext + tag together)
    c_and_tag = aes.encrypt(IV_CONST, plaintext, aad)
    
    return {
        "ciphertext_and_tag": base64.b64encode(c_and_tag).decode(),  # Complete encrypted data
        "aad": (aad.decode() if isinstance(aad, bytes) else aad),
    }

def decrypt_to_json(payload: EncryptedPayload) -> Any:
    """
    FIXED: Now uses the complete ciphertext+tag for proper decryption
    """
    key = _get_aes_key()
    aes = AESGCM(key)
    
    try:
        # Decode the complete encrypted data (ciphertext + tag together)
        c_and_tag = base64.b64decode(payload.ciphertext_and_tag)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in encrypted payload")
    
    # Prepare AAD
    aad = (payload.aad.encode() if isinstance(payload.aad, str) else AAD_CONTEXT_DEFAULT)
    
    try:
        # Decrypt using the complete ciphertext+tag (proper AES-GCM)
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

# Replace this with your actual analyze function
def analyze(req: AnalyzeRequest) -> Dict[str, Any]:
    """
    Replace this placeholder with your actual analyze function implementation.
    """
    # Your actual analyze logic goes here
    # This is just a placeholder - implement your real logic
    try:
        # Initialize Groq LLM
        llm = ChatGroq(
            groq_api_key=req.groq_api_key,
            model_name="mixtral-8x7b-32768"
        )
        
        # Initialize Exa search
        exa = Exa(api_key=req.exa_api_key)
        
        # Your actual CrewAI agents and analysis logic here
        # For now, return a sample response
        return {
            "status": "success",
            "message": "Analysis completed successfully",
            "repository": req.github_repo,
            "verbose": req.verbose,
            "analysis": {
                "security_issues": [],
                "recommendations": [],
                "summary": "Repository analysis completed"
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# ---------- FIXED encrypted endpoint ----------
@app.post("/analyze_secure")
def analyze_secure(payload: EncryptedPayload):
    """
    FIXED: Accepts AES-256-GCM encrypted request with complete ciphertext+tag,
    returns AES-256-GCM encrypted response using proper encryption/decryption.
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
    
    # Encrypt response using proper encryption
    aad_bytes = (payload.aad.encode() if isinstance(payload.aad, str) else AAD_CONTEXT_DEFAULT)
    enc = encrypt_json(result, aad=aad_bytes)
    
    return enc

# Optional: Add a test endpoint to verify encryption/decryption works
@app.post("/test_crypto")
def test_crypto():
    """
    Test endpoint to verify encryption/decryption is working correctly
    """
    test_data = {"message": "Hello, World!", "timestamp": "2025-08-30"}
    
    # Encrypt
    encrypted = encrypt_json(test_data)
    
    # Create payload object
    payload = EncryptedPayload(
        ciphertext_and_tag=encrypted["ciphertext_and_tag"],
        aad=encrypted["aad"]
    )
    
    # Decrypt
    decrypted = decrypt_to_json(payload)
    
    return {
        "original": test_data,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "success": test_data == decrypted
    }

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": "2025-08-30T13:53:00Z"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
