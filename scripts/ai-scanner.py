import subprocess
import json
import os
import sys
from datetime import datetime, timedelta

def run_command(command):
    """Executes a command and returns the result, logging errors to stderr."""
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(f"DEBUG ERROR: Command failed: {command}\nStderr: {result.stderr}", file=sys.stderr)
    return result

def get_relevant_changes(repo, pr_num):
    """
    Checks if the PR contains changes to supported source files.
    Returns (bool: has_code, list: top_level_dirs).
    """
    ext_map = {
        '.java', '.js', '.ts', '.py', '.go', '.rb', '.cs', '.cpp', '.c', '.swift'
    }
    
    cmd = f'gh pr diff {pr_num} --repo {repo} --name-only'
    res = run_command(cmd)
    if res.returncode != 0:
        return False, ["."]
    
    files = res.stdout.strip().split('\n')
    paths = set()
    found_code = False

    for f in files:
        f = f.strip()
        if not f: continue
        
        # FIX: os.path.splitext returns (root, ext). We only want the ext.
        _, ext = os.path.splitext(f)
        if ext.lower() in ext_map:
            found_code = True
            if '/' in f:
                # Extract top-level folder
                paths.add(f.split('/')[0])
            else:
                paths.add(".")
                
    return found_code, list(paths)

def main():
    one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    print(f"DEBUG: Searching for up to 50 AI PRs in active repos...", file=sys.stderr)
    
    # 1. Search for open PRs with the Claude trailer, limited to 50
    search_cmd = 'gh search prs "Co-Authored-By: Claude" --state open --limit 50 --json number,repository,title'
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

        # 2. Filter by Stars (>10) and Activity (Last Year)
        repo_data_res = run_command(f'gh repo view {repo} --json stargazerCount,pushedAt,languages')
        if repo_data_res.returncode != 0: continue
        repo_data = json.loads(repo_data_res.stdout)
        
        if repo_data.get("stargazerCount", 0) <= 10 or repo_data.get("pushedAt", "") < one_year_ago:
            continue

        # 3. Skip PR if it only changes non-code files
        has_code, changed_folders = get_relevant_changes(repo, num)
        if not has_code:
            print(f"DEBUG: Skipping {repo}#{num} - No supported source code files changed.", file=sys.stderr)
            continue

        # 4. Map supported languages for the matrix
        repo_langs = [l['node']['name'].lower() for l in repo_data.get("languages", [])]
        target_langs = [l for l in repo_langs if l in codeql_supported]
        
        for lang in target_langs:
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": title,
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}",
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
