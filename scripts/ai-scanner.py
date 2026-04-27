import subprocess
import json
import os
import sys
from datetime import datetime, timedelta

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def get_detailed_changes(repo, pr_num):
    """
    Returns a dictionary mapping detected languages to the folders they changed in.
    Example: {'java': ['android'], 'python': ['torch/csrc']}
    """
    ext_to_lang = {
        '.java': 'java', '.js': 'javascript', '.ts': 'javascript', 
        '.py': 'python', '.go': 'go', '.rb': 'ruby', 
        '.cs': 'csharp', '.cpp': 'cpp', '.c': 'cpp', '.cc': 'cpp', '.swift': 'swift'
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
                
    # Convert sets to lists
    return {k: list(v) for k, v in lang_map.items()}

def main():
    one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()
    # Languages we are willing to scan
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
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

        # 1. Basic Repo Filter
        repo_data_res = run_command(f'gh repo view {repo} --json stargazerCount,pushedAt')
        if repo_data_res.returncode != 0: continue
        repo_data = json.loads(repo_data_res.stdout)
        
        if repo_data.get("stargazerCount", 0) <= 10 or repo_data.get("pushedAt", "") < one_year_ago:
            continue

        # 2. Get specific languages changed in THIS PR
        changed_langs = get_detailed_changes(repo, num)
        if not changed_langs:
            continue

        # 3. Only add to matrix if the changed language is in our supported list
        for lang, folders in changed_langs.items():
            if lang in codeql_supported:
                matrix_include.append({
                    "pr_num": num,
                    "repo_name": repo,
                    "language": lang,
                    "pr_title": title,
                    "category_name": f"{repo.split('/')[-1]}-{num}-{lang}",
                    "scan_paths": json.dumps(folders)
                })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
