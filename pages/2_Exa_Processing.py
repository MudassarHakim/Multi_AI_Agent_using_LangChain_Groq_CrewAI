import streamlit as st
from utils.exa_utils import fetch_cybersecurity_threats, fetch_latest_cves

st.header("EXA API Threat Intelligence")

if 'exa_api' in st.session_state:
    exa_api = st.session_state['exa_api']
    st.subheader("Fetch Cybersecurity Threats")
    query = st.text_input("Threat Query", value="Latest cybersecurity threats 2024")
    if st.button("Get Threats"):
        threats = fetch_cybersecurity_threats(exa_api, query)
        st.json(threats)
    st.subheader("Fetch Latest CVEs")
    if st.button("Get CVEs"):
        cves = fetch_latest_cves(exa_api)
        st.json(cves)
else:
    st.warning("Set up the Exa API key in Home first.")
