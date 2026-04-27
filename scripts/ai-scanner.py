import subprocess
import json
import os
import sys
from datetime import datetime, timedelta

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(f"DEBUG ERROR: Command failed: {command}\nStderr: {result.stderr}", file=sys.stderr)
    return result

def get_changed_paths(repo, pr_num):
    """Returns a list of top-level directories changed in the PR."""
    cmd = f'gh pr diff {pr_num} --repo {repo} --name-only'
    res = run_command(cmd)
    if res.returncode != 0:
        return ["."]
    
    files = res.stdout.strip().split('\n')
    paths = set()
    for f in files:
        if not f.strip(): continue
        if '/' in f:
            # Add the folder name (e.g., 'src' from 'src/main/java')
            paths.add(f.split('/')[0])
        else:
            paths.add(".")
            
    # Always include the root '.' if any root files changed or to provide context
    return list(paths) if paths else ["."]

def main():
    one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    search_cmd = 'gh search prs "Co-Authored-By: Claude" --state open --limit 100 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print('matrix_data={"include":[]}')
        return

    all_prs = json.loads(search_res.stdout)
    matrix_include = []

    for pr in all_prs:
        repo = pr.get("repository", {}).get("nameWithOwner")
        num = str(pr.get("number"))
        title = pr.get("title", "Untitled")

        repo_data_res = run_command(f'gh repo view {repo} --json stargazerCount,languages,pushedAt')
        if repo_data_res.returncode != 0: continue
            
        repo_data = json.loads(repo_data_res.stdout)
        if repo_data.get("stargazerCount", 0) <= 10 or repo_data.get("pushedAt", "") < one_year_ago:
            continue

        changed_folders = get_changed_paths(repo, num)
        repo_langs = [l['node']['name'].lower() for l in repo_data.get("languages", [])]
        target_langs = [l for l in repo_langs if l in codeql_supported]
        
        for lang in target_langs:
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": title,
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}",
                # KEY FIX: Pass as a JSON list string
                "scan_paths": json.dumps(changed_folders)
            })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
