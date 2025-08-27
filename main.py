from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os, json
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

        # --- Hardcode the model name
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
            expected_output="List of recent threats.",
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
                "Fetch and analyze the latest relevant security vulnerabilities (CVEs) for this repository. "
                "Output MUST be a valid JSON array with objects containing: "
                "cve_id, severity, description, fix, reference_url"
            ),
            expected_output="JSON list of CVEs with details.",
            agent=vulnerability_researcher,
        )

        # --- Incident Response Advisor
        incident_response_advisor = Agent(
            role="Incident Response Advisor",
            goal="Suggest mitigation strategies specific to detected issues.",
            backstory="Blue-team expert mapping threats to mitigations.",
            verbose=request.verbose,
            allow_delegation=False,
            llm=llm,
        )
        incident_response_task = Task(
            description="Recommend prioritized mitigations based on threats and CVEs.",
            expected_output="List of actionable mitigations.",
            agent=incident_response_advisor,
            context=[threat_analysis_task, vulnerability_research_task],
        )

        # --- Report Writer
        cybersecurity_writer = Agent(
            role="Cybersecurity Report Writer",
            goal="Write a structured executive report on findings.",
            backstory="Veteran security report writer.",
            verbose=request.verbose,
            allow_delegation=False,
            llm=llm,
        )
        write_threat_report_task = Task(
            description="Summarize findings, vulnerabilities, and recommendations into a structured report.",
            expected_output="Executive security report.",
            agent=cybersecurity_writer,
            context=[threat_analysis_task, vulnerability_research_task, incident_response_task],
        )

        # --- Run workflow
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

        # --- Normalize results
        threats, vulns_raw, mitigations, summary = "", "", "", ""
        parsed_cves: List[Dict[str, Any]] = []

        if isinstance(results, dict) and "tasks_output" in results:
            # old structured format
            def extract(agent_role: str) -> str:
                for t in results["tasks_output"]:
                    if t.get("agent") and t["agent"].role == agent_role:
                        return t.get("raw", "")
                return ""

            threats = extract("Cybersecurity Threat Intelligence Analyst")
            vulns_raw = extract("Vulnerability Researcher")
            mitigations = extract("Incident Response Advisor")
            summary = extract("Cybersecurity Report Writer")

        else:
            # newer versions may just return text
            summary = str(results)

        # --- Try parsing JSON CVE list
        try:
            parsed_cves = json.loads(vulns_raw) if vulns_raw else []
        except Exception:
            parsed_cves = []

        return {
            "repository": request.github_repo,
            "threats": threats,
            "cves": parsed_cves,
            "mitigations": mitigations,
            "executive_summary": summary,
            "token_usage": results.get("token_usage", {}) if isinstance(results, dict) else {}
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
