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

# ---------- AES-GCM models & helpers ----------
AAD_CONTEXT_DEFAULT = b"analyze-v1"  # default associated data

class EncryptedPayload(BaseModel):
    iv: str           # base64
    ciphertext: str   # base64 (ciphertext without tag)
    tag: str          # base64 (16 bytes)
    aad: Optional[str] = None  # optional associated data (string)

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

def encrypt_json(obj: Any, aad: Optional[bytes] = None) -> EncryptedPayload:
    key = _get_aes_key()
    aes = AESGCM(key)
    iv = os.urandom(12)  # 96-bit nonce recommended
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if aad is None:
        aad = AAD_CONTEXT_DEFAULT
    c_and_tag = aes.encrypt(iv, plaintext, aad)
    ciphertext, tag = c_and_tag[:-16], c_and_tag[-16:]
    return EncryptedPayload(
        iv=base64.b64encode(iv).decode(),
        ciphertext=base64.b64encode(ciphertext).decode(),
        tag=base64.b64encode(tag).decode(),
        aad=(aad.decode() if isinstance(aad, bytes) else aad),
    )

def decrypt_to_json(payload: EncryptedPayload) -> Any:
    key = _get_aes_key()
    aes = AESGCM(key)
    try:
        iv = base64.b64decode(payload.iv)
        ct = base64.b64decode(payload.ciphertext)
        tag = base64.b64decode(payload.tag)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in encrypted payload")
    c_and_tag = ct + tag
    aad = (payload.aad.encode() if isinstance(payload.aad, str) else AAD_CONTEXT_DEFAULT)
    try:
        plaintext = aes.decrypt(iv, c_and_tag, aad)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed or invalid auth tag")
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

@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    try:
        # --- Set up API keys
        os.environ["GROQ_API_KEY"] = request.groq_api_key
        exa_client = Exa(api_key=request.exa_api_key)

        # --- Hardcode the model
        llm = ChatGroq(
            temperature=0.1,
            model_name="groq/llama3-70b-8192",
            groq_api_key=request.groq_api_key
        )

        # --- Threat Analyst
        def fetch_cybersecurity_threats(query):
            result = exa_client.search_and_contents(query)
            threat_list = []
            if hasattr(result, "results") and result.results:
                for item in result.results:
                    threat_list.append({
                        "title": getattr(item, "title", "No Title"),
                        "url": getattr(item, "url", "#"),
                        "published_date": getattr(item, "published_date", "Unknown Date"),
                        "summary": getattr(item, "summary", "No Summary"),
                    })
            return threat_list

        threat_analyst = Agent(
            role="Cybersecurity Threat Intelligence Analyst",
            goal="Gather real-time cybersecurity and repo threat intelligence.",
            backstory="Expert in code risk hunting and OSINT.",
            verbose=request.verbose,
            allow_delegation=False,
            llm=llm,
        )
        threat_analysis_task = Task(
            description=f"Analyze the GitHub repo {request.github_repo} using Exa API for security/code risks.",
            expected_output="List of recent threats (JSON array).",
            agent=threat_analyst,
            callback=lambda _: fetch_cybersecurity_threats(request.github_repo),
        )

        # --- Vulnerability Researcher
        vulnerability_researcher = Agent(
            role="Vulnerability Researcher",
            goal="Identify the latest vulnerabilities for the codebase and dependencies.",
            backstory="Specialist in code and dependency vulnerabilities.",
            verbose=request.verbose,
            allow_delegation=False,
            llm=llm,
        )
        vulnerability_research_task = Task(
            description=(
                "Fetch and analyze relevant security vulnerabilities (CVEs) for this repository. "
                "Return STRICT JSON array like:\n"
                "[{ \"cve_id\": \"CVE-XXXX\", \"severity\": \"High\", "
                "\"description\": \"...\", \"fix\": \"...\", \"reference_url\": \"...\" }]"
            ),
            expected_output="JSON array of CVEs",
            agent=vulnerability_researcher,
        )

        # --- Incident Response Advisor
        incident_response_advisor = Agent(
            role="Incident Response Advisor",
            goal="Suggest mitigation strategies for the identified vulnerabilities.",
            backstory="Blue-team expert mapping threats to mitigations.",
            verbose=request.verbose,
            allow_delegation=False,
            llm=llm,
        )
        incident_response_task = Task(
            description=(
                "Given the identified CVEs, return STRICT JSON array of mitigations:\n"
                "[{ \"cve_id\": \"CVE-XXXX\", \"mitigation\": \"...\" }]"
            ),
            expected_output="JSON array of mitigations",
            agent=incident_response_advisor,
            context=[vulnerability_research_task],
        )

        # --- Report Writer
        cybersecurity_writer = Agent(
            role="Cybersecurity Report Writer",
            goal="Write an executive summary in polished prose.",
            backstory="Veteran security report writer.",
            verbose=request.verbose,
            allow_delegation=False,
            llm=llm,
        )
        write_threat_report_task = Task(
            description="Summarize CVEs and mitigations into an executive summary (plain text, not JSON).",
            expected_output="Executive summary text",
            agent=cybersecurity_writer,
            context=[vulnerability_research_task, incident_response_task],
        )

        # --- Run Crew
        crew = Crew(
            agents=[threat_analyst, vulnerability_researcher, incident_response_advisor, cybersecurity_writer],
            tasks=[threat_analysis_task, vulnerability_research_task, incident_response_task, write_threat_report_task],
            verbose=request.verbose,
            process=Process.sequential,
            full_output=True,
            share_crew=False,
            manager_llm=llm,
        )
        results = crew.kickoff()

        # --- Normalize outputs
        threats, vulns_raw, mitigations_raw, summary = [], "[]", "[]", ""
        if isinstance(results, dict) and "tasks_output" in results:
            def extract(role: str):
                for t in results["tasks_output"]:
                    if t.get("agent") and t["agent"].role == role:
                        return t.get("raw", "")
                return ""
            threats = extract("Cybersecurity Threat Intelligence Analyst")
            vulns_raw = extract("Vulnerability Researcher")
            mitigations_raw = extract("Incident Response Advisor")
            summary = extract("Cybersecurity Report Writer")
        else:
            summary = str(results)

        # --- Safe JSON parse
        def safe_parse(raw: str, fallback: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, list) else fallback
            except Exception:
                return fallback

        parsed_cves = safe_parse(vulns_raw, [])
        parsed_mitigations = safe_parse(mitigations_raw, [])

        # --- Fallback: extract from executive summary if empty
        if not parsed_cves and summary:
            cve_pattern = re.compile(r"(CVE-\d{4}-\d+)")
            matches = cve_pattern.findall(summary)
            for cve in set(matches):
                parsed_cves.append({
                    "cve_id": cve,
                    "severity": "Unknown",
                    "description": f"See executive summary for details on {cve}.",
                    "fix": "Refer to mitigation section.",
                    "reference_url": f"https://nvd.nist.gov/vuln/detail/{cve}"
                })

        if not parsed_mitigations and parsed_cves and summary:
            for cve in parsed_cves:
                mitigation = ""
                match = re.search(rf"{cve['cve_id']}.*?(upgrade[^.]+)", summary, re.IGNORECASE)
                if match:
                    mitigation = match.group(1)
                parsed_mitigations.append({
                    "cve_id": cve["cve_id"],
                    "mitigation": mitigation or "See executive summary for mitigation details."
                })

        return {
            "repository": request.github_repo,
            "threats": threats,
            "cves": parsed_cves,
            "mitigations": parsed_mitigations,
            "executive_summary": summary,
            "token_usage": results.get("token_usage", {}) if isinstance(results, dict) else {}
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------- New encrypted endpoint ----------
@app.post("/analyze_secure")
def analyze_secure(payload: EncryptedPayload):
    """
    Accepts AES-256-GCM encrypted request, returns AES-256-GCM encrypted response.
    Request plaintext must be the same JSON as AnalyzeRequest.
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

    # Encrypt response with same/supplied AAD (or default)
    aad_bytes = (payload.aad.encode() if isinstance(payload.aad, str) else AAD_CONTEXT_DEFAULT)
    enc = encrypt_json(result, aad=aad_bytes)
    return enc
