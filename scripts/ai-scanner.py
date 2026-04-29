import subprocess
import json
import os
import sys
from datetime import datetime, timedelta

def run_command(command):
    """Executes a command and returns the result, logging errors to stderr."""
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def get_detailed_changes(repo, pr_num):
    ext_to_lang = {
        '.java': 'java', '.js': 'javascript', '.ts': 'javascript', 
        '.py': 'python', '.rb': 'ruby'
    }
    
    cmd = f'gh pr diff {pr_num} --repo {repo} --name-only'
    res = run_command(cmd)
    if res.returncode != 0:
        return {}
    
    files = res.stdout.strip().split('\n')
    lang_map = {}

    for f in files:
        f = f.strip()
        if not f: continue
        
        _, ext = os.path.splitext(f)
        lang = ext_to_lang.get(ext.lower())
        
        if lang:
            if lang not in lang_map:
                lang_map[lang] = set()
            if '/' in f:
                lang_map[lang].add(f.split('/')[0])
            else:
                lang_map[lang].add(".")
                
    return {k: list(v) for k, v in lang_map.items()}

def main():
    one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()
    codeql_supported = ["java", "javascript", "python", "ruby"]
    
    # --- UPDATED LIMITS ---
    MAX_PR_LINES = 2500 
    SEARCH_LIMIT = 500
    
    print(f"DEBUG: Searching for AI PRs (Limit {SEARCH_LIMIT} search, Max {MAX_PR_LINES} lines)", file=sys.stderr)
    
    search_cmd = f'gh search prs "Co-Authored-By: Claude" --state open --limit {SEARCH_LIMIT} --json number,repository,title'
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print('matrix_data={"include":[]}')
        return

    all_prs = json.loads(search_res.stdout)
    matrix_include = []
    seen_repos = {} 

    for pr in all_prs:
        repo = pr.get("repository", {}).get("nameWithOwner")
        if repo in seen_repos: continue

        num = str(pr.get("number"))
        title = pr.get("title", "Untitled")

        # Size Filtering
        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        total_changes = 0
        if lines_res.returncode == 0:
            stats = json.loads(lines_res.stdout)
            total_changes = stats.get("additions", 0) + stats.get("deletions", 0)
            if total_changes > MAX_PR_LINES:
                print(f"DEBUG: Skipping {repo}#{num} - Too large ({total_changes} lines)", file=sys.stderr)
                continue

        repo_data_res = run_command(f'gh repo view {repo} --json stargazerCount,pushedAt,languages')
        if repo_data_res.returncode != 0: continue
        repo_data = json.loads(repo_data_res.stdout)
        
        if repo_data.get("stargazerCount", 0) <= 10 or repo_data.get("pushedAt", "") < one_year_ago:
            continue

        changed_langs = get_detailed_changes(repo, num)
        if not changed_langs: continue

        repo_supported_langs = [l['node']['name'].lower() for l in repo_data.get("languages", [])]
        
        added_any = False
        for lang, folders in changed_langs.items():
            if lang in codeql_supported and lang in repo_supported_langs:
                matrix_include.append({
                    "pr_num": num,
                    "repo_name": repo,
                    "language": lang,
                    "pr_title": title,
                    "category_name": f"{repo.split('/')[-1]}-{num}-{lang}",
                    "scan_paths": json.dumps(folders)
                })
                added_any = True
        
        if added_any:
            seen_repos[repo] = {"num": num, "stars": repo_data.get("stargazerCount"), "size": total_changes}

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
