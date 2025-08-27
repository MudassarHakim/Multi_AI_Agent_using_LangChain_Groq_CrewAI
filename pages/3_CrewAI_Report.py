import streamlit as st
from utils.crewai_utils import run_crewai_intelligence

st.header("AI Multi-Agent Cybersecurity Report")

if 'groq_api' in st.session_state and 'exa_api' in st.session_state:
    if st.button("Run Multi-Agent Report"):
        report = run_crewai_intelligence(
            st.session_state['groq_api'], 
            st.session_state['exa_api']
        )
        st.markdown(report, unsafe_allow_html=True)
else:
    st.warning("Set up Groq and Exa API keys in Home first.")
