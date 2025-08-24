import os
import tempfile
import shutil
import subprocess
from pathlib import Path
import streamlit as st

# ---------------------------
# Helpers
# ---------------------------

def clone_repo(repo_url: str) -> str:
    """Clone GitHub repo to a temporary folder, return the path."""
    tmp_dir = tempfile.mkdtemp()
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(tmp_dir, repo_name)
    subprocess.run(["git", "clone", repo_url, repo_path], check=True)
    return repo_path

def build_file_tree(base_path: str):
    """Return a nested dict representing the file tree."""
    tree = {}
    for root, dirs, files in os.walk(base_path):
        rel_root = os.path.relpath(root, base_path)
        if rel_root == ".":
            rel_root = ""
        tree[rel_root] = {"dirs": dirs, "files": files}
    return tree

def render_file_tree(tree, base_path, selected_files):
    """Render a file tree with checkboxes in sidebar."""
    for folder, content in tree.items():
        # Display folder
        if folder:
            st.sidebar.markdown(f"**{folder}/**")

        # Display files
        for f in content["files"]:
            file_path = os.path.join(folder, f) if folder else f
            checked = st.sidebar.checkbox(file_path, value=False)
            if checked:
                selected_files.append(os.path.join(base_path, file_path))

def read_file(file_path: str, max_chars=5000):
    """Read file content safely (truncate if too big)."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if len(content) > max_chars:
            content = content[:max_chars] + "\n\n... [TRUNCATED]"
        return content
    except Exception as e:
        return f"Error reading {file_path}: {e}"

def run_crewai_analysis(files: list[str], groq_key: str, exa_key: str) -> str:
    """Stub for CrewAI pipeline — replace with actual logic."""
    report = "# Repo Analysis Report\n\n"
    report += f"**Files analyzed** ({len(files)}):\n"
    report += "\n".join([f"- {Path(f).name}" for f in files])
    report += "\n\n## Findings\n\n"
    report += "- (Placeholder) Security issues found...\n"
    report += "- (Placeholder) Code quality recommendations...\n"
    report += "- (Placeholder) Observability suggestions...\n"
    return report

# ---------------------------
# Streamlit UI
# ---------------------------

st.set_page_config(page_title="Repo Analyzer", layout="wide")

st.title("🔍 GitHub Repo Analyzer")

# Sidebar inputs
st.sidebar.header("Configuration")
repo_url = st.sidebar.text_input("GitHub Repo URL", placeholder="https://github.com/user/repo.git")

groq_key = st.sidebar.text_input("Groq API Key", type="password")
st.sidebar.markdown("[Get a key](https://console.groq.com)")

exa_key = st.sidebar.text_input("Exa API Key", type="password")
st.sidebar.markdown("[Get a key](https://exa.ai)")

st.sidebar.markdown("---")
disclaimer = st.sidebar.checkbox("I understand keys are only used for this session.", value=True)

# Repo fetch
if st.sidebar.button("📥 Fetch Repo", disabled=not repo_url):
    with st.spinner("Cloning repo..."):
        try:
            repo_path = clone_repo(repo_url)
            st.session_state["repo_path"] = repo_path
            st.success(f"Cloned repo to {repo_path}")
        except Exception as e:
            st.error(f"Failed to clone repo: {e}")

# File tree & preview
selected_files = []
if "repo_path" in st.session_state:
    repo_path = st.session_state["repo_path"]
    tree = build_file_tree(repo_path)
    st.sidebar.header("📂 File Explorer")
    render_file_tree(tree, repo_path, selected_files)

    # Preview file
    st.subheader("📄 File Preview")
    clicked_file = st.selectbox("Select file to preview", selected_files or [])
    if clicked_file:
        st.code(read_file(clicked_file), language="python")

# Run analysis
if st.sidebar.button("🚀 Run Analysis", disabled="repo_path" not in st.session_state):
    with st.spinner("Running CrewAI analysis..."):
        repo_path = st.session_state["repo_path"]
        files_to_analyze = selected_files or [
            str(p) for p in Path(repo_path).rglob("*") if p.is_file()
        ]
        report = run_crewai_analysis(files_to_analyze, groq_key, exa_key)
        st.session_state["analysis_report"] = report
        st.success("Analysis completed!")

# Show analysis
if "analysis_report" in st.session_state:
    st.subheader("📊 Analysis Report")
    st.markdown(st.session_state["analysis_report"])

    st.download_button(
        "⬇️ Download Report (Markdown)",
        st.session_state["analysis_report"],
        "repo_analysis.md",
        "text/markdown",
    )

# Cleanup old repos (optional)
if st.sidebar.button("🗑️ Clear Session"):
    if "repo_path" in st.session_state:
        shutil.rmtree(st.session_state["repo_path"], ignore_errors=True)
    st.session_state.clear()
    st.success("Session cleared.")
