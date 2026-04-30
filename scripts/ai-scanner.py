import subprocess
import json
import os
import sys
import pandas as pd

def run_command(command):
    """Executes a command and returns the result."""
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # --- CONFIGURATION ---
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 2500
    SCAN_LIMIT = 20  # Limit to the first 20 valid PRs
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []
    seen_repos = set()
    found_count = 0

    for _, row in df.iterrows():
        # Stop once we hit the test limit
        if found_count >= SCAN_LIMIT:
            break

        repo = row['repo_name']
        num = str(row['number'])
        lang = row['primary_language']
        agent = row['agent_name']
        title = row.get('title', 'Untitled')

        if repo in seen_repos:
            continue

        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res.returncode == 0:
            stats = json.loads(lines_res.stdout)
            total_changes = stats.get("additions", 0) + stats.get("deletions", 0)
            if total_changes > MAX_PR_LINES:
                continue
        else:
            continue

        matrix_include.append({
            "pr_num": num,
            "repo_name": repo,
            "language": lang,
            "pr_title": title,
            "agent_name": agent,
            "category_name": f"{repo.replace('/', '_SLASH_')}--{num}--{lang}--{agent.replace(' ', '_')}"
        })
        
        seen_repos.add(repo)
        found_count += 1

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
