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

def main():
    # Calculate date for 1 year ago (ISO 8601 format)
    one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()
    print(f"DEBUG: Searching for AI PRs in active repos (Updated since: {one_year_ago})", file=sys.stderr)
    
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    # 1. Search for open PRs with the Claude trailer
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

        # 2. Fetch repository metadata (Stars + Last Updated + Languages)
        # 'pushedAt' represents the last time code was pushed to the repo
        repo_data_res = run_command(f'gh repo view {repo} --json stargazersCount,languages,pushedAt')
        if repo_data_res.returncode != 0:
            continue
            
        repo_data = json.loads(repo_data_res.stdout)
        stars = repo_data.get("stargazersCount", 0)
        pushed_at = repo_data.get("pushedAt", "")

        # 3. Apply Filters: >10 Stars AND Pushed in the last year
        if stars <= 10:
            continue
        if pushed_at < one_year_ago:
            print(f"DEBUG: Skipping {repo} - Stale (Last pushed: {pushed_at})", file=sys.stderr)
            continue

        print(f"DEBUG: Processing {repo} (Stars: {stars}, Updated: {pushed_at})", file=sys.stderr)

        # 4. Detect supported languages
        repo_langs = [l['node']['name'].lower() for l in repo_data.get("languages", [])]
        target_langs = [l for l in repo_langs if l in codeql_supported]
        
        for lang in target_langs:
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": title,
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}"
            })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
