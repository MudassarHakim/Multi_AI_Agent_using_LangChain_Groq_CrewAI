from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os, json, re
from typing import List, Dict, Any

from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from exa_py import Exa

app = FastAPI()

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
                # Try to find mitigation sentences mentioning the CVE
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
