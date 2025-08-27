import streamlit as st

st.title("Multi-Agent Cybersecurity Platform")

with st.form("credentials_form"):
    groq_api = st.text_input("Groq API Key", type="password")
    exa_api = st.text_input("Exa API Key", type="password")
    github_repo = st.text_input("GitHub Repo URL", value="https://github.com/your/repo")
    submitted = st.form_submit_button("Save Credentials")
    if submitted:
        st.session_state['groq_api'] = groq_api
        st.session_state['exa_api'] = exa_api
        st.session_state['github_repo'] = github_repo
        st.success("Credentials saved! Choose a task from the sidebar.")

st.markdown("Navigate using the sidebar for each task.")
