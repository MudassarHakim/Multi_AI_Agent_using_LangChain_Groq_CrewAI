import os
import subprocess
import tempfile
from pathlib import Path

import streamlit as st

# ---------------------------
# Helper: Sanitize GitHub URL
# ---------------------------
def sanitize_repo_url(repo_url: str) -> str:
    # Remove query params (e.g. ?utm_source=...)
    repo_url = repo_url.split("?")[0].strip()
    # Remove trailing slashes
    repo_url = repo_url.rstrip("/")
    return repo_url


# ---------------------------
# Helper: Clone GitHub repo
# ---------------------------
def clone_repo(repo_url: str) -> str:
    repo_url = sanitize_repo_url(repo_url)
    repo_path = tempfile.mkdtemp()
    try:
        subprocess.check_call(["git", "clone", repo_url, repo_path])
        return repo_path
    except subprocess.CalledProcessError as e:
        st.error(f"Failed to clone repo: {e}")
        return None


# ---------------------------
# Helper: Build file tree
# ---------------------------
def build_file_tree(repo_path: str, extensions=(".py",)):
    file_tree = {}
    for root, dirs, files in os.walk(repo_path):
        rel_root = os.path.relpath(root, repo_path)
        if rel_root == ".":
            rel_root = ""
        file_tree[rel_root] = [
            f for f in files if f.endswith(extensions)
        ]
    return file_tree


# ---------------------------
# Streamlit App
# ---------------------------
st.set_page_config(page_title="Repo Vulnerability Explorer", layout="wide")
st.title("🔍 GitHub Repo Vulnerability Explorer")

repo_url = st.text_input("Enter GitHub repository URL", "")

if repo_url:
    repo_path = clone_repo(repo_url)
    if repo_path:
        st.sidebar.subheader("📂 Repository File Explorer")
        file_tree = build_file_tree(repo_path)

        # Show folders and files in sidebar
        selected_files = []
        for folder, files in file_tree.items():
            if folder:
                st.sidebar.markdown(f"**{folder}/**")
            for f in files:
                full_path = os.path.join(repo_path, folder, f)
                if st.sidebar.checkbox(f, key=full_path):
                    selected_files.append(full_path)

        run_all = st.sidebar.checkbox("Run on ALL files", value=False)

        # Main panel
        st.subheader("📄 File Preview")

        files_to_process = selected_files if not run_all else [
            os.path.join(repo_path, folder, f)
            for folder, files in file_tree.items()
            for f in files
        ]

        if files_to_process:
            for file_path in files_to_process:
                st.markdown(f"### `{os.path.relpath(file_path, repo_path)}`")
                with open(file_path, "r", encoding="utf-8") as f:
                    code = f.read()
                st.code(code, language="python")
        else:
            st.info("Select files from the sidebar to preview or run analysis.")
