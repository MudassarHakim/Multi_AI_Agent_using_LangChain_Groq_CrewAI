import streamlit as st
from utils.github_scanner import scan_github_repo

st.header("Repository Vulnerability Scanner")

if 'github_repo' in st.session_state:
    repo_url = st.session_state['github_repo']
    if st.button("Scan Repository"):
        result = scan_github_repo(repo_url)
        st.json(result)
else:
    st.warning("First set up API keys and repo in Home.")
