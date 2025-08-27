import tempfile
import git
import os

def scan_github_repo(repo_url):
    try:
        tmpdir = tempfile.mkdtemp()
        git.Repo.clone_from(repo_url, tmpdir)
        suspicious_files = {}
        for root, dirs, files in os.walk(tmpdir):
            for file in files:
                path = os.path.join(root, file)
                try:
                    with open(path, errors="ignore") as f:
                        lines = f.readlines()
                        findings = [line.strip() for line in lines if "API_KEY" in line or "SECRET" in line or "password" in line]
                        if findings:
                            suspicious_files[os.path.relpath(path, tmpdir)] = findings
                except Exception:
                    continue
        return suspicious_files or {"message": "No secrets found."}
    except Exception as e:
        return {"error": str(e)}
