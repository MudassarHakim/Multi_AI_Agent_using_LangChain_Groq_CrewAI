import streamlit as st
import os
from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq
from exa_py import Exa
from datetime import datetime

st.title("Multi-AI Cybersecurity Agent Suite")

# User Inputs
groq_api_key = st.text_input("Enter your GROQ API Key:", type="password")
exa_api_key = st.text_input("Enter your Exa API Key:", type="password")
github_project = st.text_input("Enter the GitHub Project (URL or repo name) to evaluate:")

run_button = st.button("Run Vulnerability Assessment")

if run_button and groq_api_key and exa_api_key and github_project:
    os.environ["GROQ_API_KEY"] = groq_api_key
    exa_client = Exa(api_key=exa_api_key)
    llm = ChatGroq(temperature=0, model_name="llama3-70b-8192")
    today = datetime.now().strftime("%Y-%m-%d")

    def fetch_cybersecurity_threats(query):
        result = exa_client.search_and_contents(query, summary=True)
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

    def fetch_latest_cves():
        cve_query = "Latest CVEs and security vulnerabilities 2024"
        result = exa_client.search_and_contents(cve_query, summary=True)
        cve_list = []
        if hasattr(result, "results") and result.results:
            for item in result.results[:5]:
                cve_list.append({
                    "title": getattr(item, "title", "No Title"),
                    "url": getattr(item, "url", "#"),
                    "published_date": getattr(item, "published_date", "Unknown Date"),
                    "summary": getattr(item, "summary", "No Summary"),
                })
        return cve_list

    def fetch_github_vulns(repo):
        gh_query = f"Security vulnerabilities, CVEs, security advisories for {repo}"
        result = exa_client.search_and_contents(gh_query, summary=True)
        vuln_list = []
        if hasattr(result, "results") and result.results:
            for item in result.results:
                vuln_list.append({
                    "title": getattr(item, "title", "No Title"),
                    "url": getattr(item, "url", "#"),
                    "published_date": getattr(item, "published_date", "Unknown Date"),
                    "summary": getattr(item, "summary", "No Summary"),
                })
        return vuln_list

    # Agents and tasks
    threat_analyst = Agent(
        role="Cybersecurity Threat Intelligence Analyst",
        goal="Gather real-time cybersecurity threat intelligence.",
        backstory="You're an expert in cybersecurity, tracking emerging threats, malware campaigns, and hacking incidents.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )

    vulnerability_researcher = Agent(
        role="Vulnerability Researcher",
        goal="Identify the latest software vulnerabilities and security flaws.",
        backstory="You're a cybersecurity researcher specializing in vulnerability analysis and threat mitigation.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )

    github_vuln_researcher = Agent(
        role="GitHub Project Vulnerability Researcher",
        goal="Retrieve and analyze security vulnerabilities for the given GitHub project.",
        backstory="Experienced in open-source security and tracking vulnerabilities in software repositories.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )

    incident_response_advisor = Agent(
        role="Incident Response Advisor",
        goal="Provide mitigation strategies for detected threats and vulnerabilities.",
        backstory="You specialize in cybersecurity defense strategies for prompt mitigation.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )

    cybersecurity_writer = Agent(
        role="Cybersecurity Report Writer",
        goal="Generate a structured cybersecurity threat report based on collected intelligence.",
        backstory="Expert in summarizing security reports and providing executive-level insights.",
        verbose=True,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=True,
    )

    threat_analysis_task = Task(
        description=f"Use EXA API to retrieve the latest cybersecurity threats for {today}. Provide a summary of the top threats.",
        expected_output="A structured list of recent cybersecurity threats, including malware trends and cyberattacks.",
        agent=threat_analyst,
        callback=lambda inputs: fetch_cybersecurity_threats("Latest cybersecurity threats 2024"),
    )

    vulnerability_research_task = Task(
        description="Fetch and analyze the latest security vulnerabilities (CVEs).",
        expected_output="A structured list of newly discovered CVEs and their impact.",
        agent=vulnerability_researcher,
        callback=lambda inputs: fetch_latest_cves(),
    )

    github_vuln_task = Task(
        description=f"Analyze the specified GitHub project ({github_project}) for recent vulnerabilities, CVEs, and security advisories.",
        expected_output="A structured list of GitHub project vulnerabilities and relevant security information.",
        agent=github_vuln_researcher,
        callback=lambda inputs: fetch_github_vulns(github_project),
    )

    incident_response_task = Task(
        description="Analyze cybersecurity threats and vulnerabilities to suggest mitigation strategies.",
        expected_output="A list of recommended defensive actions against active threats.",
        agent=incident_response_advisor,
        context=[threat_analysis_task, vulnerability_research_task, github_vuln_task]
    )

    write_threat_report_task = Task(
        description="Summarize all the above intelligence into a comprehensive cybersecurity threat report.",
        expected_output="A report containing key threats, CVEs, GitHub project vulnerabilities, and mitigation recommendations.",
        agent=cybersecurity_writer,
        context=[threat_analysis_task, vulnerability_research_task, github_vuln_task, incident_response_task]
    )

    crew = Crew(
        agents=[threat_analyst, vulnerability_researcher, github_vuln_researcher, incident_response_advisor, cybersecurity_writer],
        tasks=[threat_analysis_task, vulnerability_research_task, github_vuln_task, incident_response_task, write_threat_report_task],
        verbose=2,
        process=Process.sequential,
        full_output=True,
        share_crew=False,
        manager_llm=llm,
        max_iter=15,
    )

    with st.spinner("Running multi-agent analysis..."):
        results = crew.kickoff()
        st.markdown(results['final_output'])
else:
    st.info("Please provide all required inputs and click 'Run Vulnerability Assessment'.")
