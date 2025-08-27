from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os

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
        # --- Set up API keys for Groq and Exa
        os.environ["GROQ_API_KEY"] = request.groq_api_key
        exa_client = Exa(api_key=request.exa_api_key)

        # --- Hardcode the model name with provider prefix
        model_name1 = "groq/llama3-70b-8192"
        
        llm = ChatGroq(
            temperature=0.1,
            model_name=model_name1,
            groq_api_key=request.groq_api_key  # explicitly pass key
        )

        # --- Agent 1: Threat Analyst
        def fetch_cybersecurity_threats(query):
            result = exa_client.search_and_contents(query)
            threat_list = []
            if hasattr(result, "results") and result.results:
                for item in result.results:
                    threat_list.append(
                        f"Title: {getattr(item, 'title', 'No Title')}\n"
                        f"URL: {getattr(item, 'url', '#')}\n"
                        f"Published: {getattr(item, 'published_date', 'Unknown Date')}\n"
                        f"Summary: {getattr(item, 'summary', 'No Summary')}\n"
                    )
            return "\n\n".join(threat_list) if threat_list else "No threats found."


        threat_analyst = Agent(
            role="Cybersecurity Threat Intelligence Analyst",
            goal="Gather real-time cybersecurity and repo threat intelligence.",
            backstory="An expert in cybersecurity, code risk hunting, and open source intelligence using LLMs.",
            verbose=True,
            allow_delegation=False,
            llm=llm,
            max_iter=5,
            memory=True,
        )
        threat_analysis_task = Task(
            description=f"Analyze the GitHub repo {request.github_repo} using Exa API for security/code risks and summarize threats.",
            expected_output="A list of recent code, dependency, or repository threats.",
            agent=threat_analyst,
            callback=lambda _: fetch_cybersecurity_threats(request.github_repo),
        )

        # --- Agent 2: Vulnerability Researcher
        def fetch_latest_cves():
            cve_query = "Latest CVEs and security vulnerabilities"
            result = exa_client.search_and_contents(cve_query)
            cve_list = []
            if hasattr(result, "results") and result.results:
                for item in result.results[:5]:
                    cve_list.append(
                        f"Title: {getattr(item, 'title', 'No Title')}\n"
                        f"URL: {getattr(item, 'url', '#')}\n"
                        f"Published: {getattr(item, 'published_date', 'Unknown Date')}\n"
                        f"Summary: {getattr(item, 'summary', 'No Summary')}\n"
                    )
            return "\n\n".join(cve_list) if cve_list else "No CVEs found."


        vulnerability_researcher = Agent(
            role="Vulnerability Researcher",
            goal="Identify the latest vulnerabilities for the codebase and dependencies.",
            backstory="A specialist in code, dependency, and supply chain vulnerabilities.",
            verbose=True,
            allow_delegation=False,
            llm=llm,
            max_iter=5,
            memory=True,
        )
        vulnerability_research_task = Task(
            description="Fetch and analyze the latest relevant security vulnerabilities (CVEs) for this repository.",
            expected_output="A brief list of recent CVEs and their relevance or impact.",
            agent=vulnerability_researcher,
            callback=lambda _: fetch_latest_cves(),
        )

        # --- Agent 3: Incident Response Advisor
        incident_response_advisor = Agent(
            role="Incident Response Advisor",
            goal="Suggest mitigation strategies specific to the detected issues.",
            backstory="A blue-team expert mapping threats to actionable remediations.",
            verbose=True,
            allow_delegation=False,
            llm=llm,
            max_iter=5,
            memory=True,
        )
        incident_response_task = Task(
            description="Analyze found threats and vulnerabilities and recommend best mitigation and response strategies for the repository.",
            expected_output="List of prioritized, actionable mitigations.",
            agent=incident_response_advisor,
            context=[threat_analysis_task, vulnerability_research_task],
        )

        # --- Agent 4: Report Writer
        cybersecurity_writer = Agent(
            role="Cybersecurity Report Writer",
            goal="Write a clear, structured executive report on the findings.",
            backstory="A veteran security report writer, skilled at concise, readable, actionable summaries.",
            verbose=True,
            allow_delegation=False,
            llm=llm,
            max_iter=5,
            memory=True,
        )
        write_threat_report_task = Task(
            description="Summarize all findings, vulnerabilities, and recommendations into a professional GitHub repository security intelligence report.",
            expected_output="A comprehensive report including threats, vulnerabilities, and suggested actions.",
            agent=cybersecurity_writer,
            context=[threat_analysis_task, vulnerability_research_task, incident_response_task],
        )

        # --- Run the multi-agent workflow
        crew = Crew(
            agents=[threat_analyst, vulnerability_researcher, incident_response_advisor, cybersecurity_writer],
            tasks=[threat_analysis_task, vulnerability_research_task, incident_response_task, write_threat_report_task],
            verbose=True,
            process=Process.sequential,
            full_output=True,
            share_crew=False,
            manager_llm=llm,
            max_iter=15,
        )
        results = crew.kickoff()
        return {"result": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
