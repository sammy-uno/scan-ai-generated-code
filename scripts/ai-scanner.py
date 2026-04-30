import subprocess
import json
import os
import sys
import pandas as pd

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 2500
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []

    for _, row in df.iterrows():
        repo, num, lang, agent = row['repo_name'], str(row['number']), row['primary_language'], row['agent_name']

        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res.returncode == 0:
            stats = json.loads(lines_res.stdout)
            if (stats.get("additions", 0) + stats.get("deletions", 0)) > MAX_PR_LINES:
                continue
            
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": row.get('title', 'Untitled'),
                "agent_name": agent,
                "category_name": f"{repo.replace('/', '_SLASH_')}--{num}--{lang}--{agent.replace(' ', '_')}"
            })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
