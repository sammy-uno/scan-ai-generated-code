import subprocess, json, os, time, pandas as pd

def run_command(command, max_retries=2):
    for attempt in range(max_retries):
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0: return result
            time.sleep(2)
        except subprocess.TimeoutExpired: continue
    return None

def main():
    # --- CONFIGURATION ---
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 1000 
    SCAN_LIMIT = 100    # Updated to 100
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []
    seen_repos = set()
    found_count = 0

    for _, row in df.iterrows():
        if found_count >= SCAN_LIMIT: break
        repo, num, lang, agent = row['repo_name'], str(row['number']), row['primary_language'], row['agent_name']
        title = row.get('title', 'Untitled')

        if repo in seen_repos: continue

        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res and lines_res.returncode == 0:
            stats = json.loads(lines_res.stdout)
            if (stats.get("additions", 0) + stats.get("deletions", 0)) > MAX_PR_LINES: continue
        else: continue

        matrix_include.append({
            "pr_num": num, "repo_name": repo, "language": lang, "pr_title": title, "agent_name": agent,
            "category_name": f"{repo.replace('/', '_SLASH_')}--{num}--{lang}--{agent.replace(' ', '_')}"
        })
        seen_repos.add(repo); found_count += 1

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f: f.write(f"matrix_data={output}\n")
    else: print(f"matrix_data={output}")

if __name__ == "__main__": main()
