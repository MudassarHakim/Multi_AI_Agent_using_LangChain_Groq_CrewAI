import os
from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from exa_py import Exa

def run_crewai_report(groq_key, exa_key):
    os.environ["GROQ_API_KEY"] = groq_key
    exa_client = Exa(api_key=exa_key)
    llm = ChatGroq(temperature=0, model_name="llama3-70b-8192")
    
    # === Agents ===
    def fetch_cybersecurity_threats(query):
        result = exa_client.search_and_contents(query, summary=True)
        threats = []
        for item in getattr(result, "results", []):
            threats.append({
                "title": getattr(item, "title", "No Title"),
                "url": getattr(item, "url", "#"),
                "published_date": getattr(item, "published_date", "Unknown Date"),
                "summary": getattr(item, "summary", "No Summary"),
            })
        return threats

    def fetch_latest_cves():
        result = exa_client.search_and_contents("Latest CVEs and security vulnerabilities 2024", summary=True)
        cves = []
        for item in getattr(result, "results", [])[:5]:
            cves.append({
                "title": getattr(item, "title", "No Title"),
                "url": getattr(item, "url", "#"),
                "published_date": getattr(item, "published_date", "Unknown Date"),
                "summary": getattr(item, "summary", "No Summary"),
            })
        return cves

    # Threat analyst agent
    threat_analyst = Agent(
        role="Cybersecurity Threat Intelligence Analyst",
        goal="Gather real-time cybersecurity threat intelligence.",
        backstory="Expert in cybersecurity, tracking emerging threats, malware campaigns, and hacking incidents.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )
    threat_analysis_task = Task(
        description="Use EXA API to retrieve latest cybersecurity threats. Provide a summary of the top threats.",
        expected_output="A structured list of recent cybersecurity threats, including malware trends and cyberattacks.",
        agent=threat_analyst,
        callback=lambda inputs: fetch_cybersecurity_threats("Latest cybersecurity threats 2024"),
    )

    # Vulnerability researcher agent
    vulnerability_researcher = Agent(
        role="Vulnerability Researcher",
        goal="Identify the latest software vulnerabilities and security flaws.",
        backstory="Specializes in vulnerability analysis.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )
    vulnerability_research_task = Task(
        description="Fetch and analyze the latest security vulnerabilities (CVEs).",
        expected_output="A structured list of newly discovered CVEs and their impact.",
        agent=vulnerability_researcher,
        callback=lambda inputs: fetch_latest_cves(),
    )

    # Incident response advisor
    incident_response_advisor = Agent(
        role="Incident Response Advisor",
        goal="Provide mitigation strategies for detected threats and vulnerabilities.",
        backstory="Specialist in cybersecurity defense strategies.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )
    incident_response_task = Task(
        description="Analyze cybersecurity threats and vulnerabilities to suggest mitigation strategies.",
        expected_output="A list of recommended defensive actions against active threats.",
        agent=incident_response_advisor,
        context=[threat_analysis_task, vulnerability_research_task],
    )

    # Cybersecurity report writer
    cybersecurity_writer = Agent(
        role="Cybersecurity Report Writer",
        goal="Generate a structured cybersecurity threat report based on collected intelligence.",
        backstory="Experienced cybersecurity analyst producing executive-level reports.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )
    write_threat_report_task = Task(
        description="Summarize the cybersecurity threat intelligence, vulnerabilities, and response strategies into a report.",
        expected_output="A comprehensive cybersecurity intelligence report with key threats, vulnerabilities, and recommendations.",
        agent=cybersecurity_writer,
        context=[threat_analysis_task, vulnerability_research_task, incident_response_task],
    )

    crew = Crew(
        agents=[threat_analyst, vulnerability_researcher, incident_response_advisor, cybersecurity_writer],
        tasks=[threat_analysis_task, vulnerability_research_task, incident_response_task, write_threat_report_task],
        verbose=2,
        process=Process.sequential,
        full_output=True,
        share_crew=False,
        manager_llm=llm,
        max_iter=15,
    )
    results = crew.kickoff()
    if isinstance(results, dict):
        # CrewAI typically returns a dict with 'final_output'
        return results.get('final_output', str(results))
    return str(results)
