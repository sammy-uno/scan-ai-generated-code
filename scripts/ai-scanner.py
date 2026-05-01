import subprocess
import json
import os
import time
import pandas as pd

def run_command(command, max_retries=2):
    """Executes a command with a 30s timeout and internal retries."""
    for attempt in range(max_retries):
        try:
            # Added timeout to prevent hanging if GitHub CLI stalls
            result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0:
                return result
            print(f"Command failed (Attempt {attempt + 1}): {result.stderr}")
            time.sleep(2) # Short backoff before retry
        except subprocess.TimeoutExpired:
            print(f"Command timed out (Attempt {attempt + 1})")
            continue
    return None

def main():
    # --- CONFIGURATION ---
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 1000  # Updated limit
    SCAN_LIMIT = 100     # Updated limit
    
    # ADDED: Skip specific repositories
    EXCLUDE_REPOS = [
        "BerriAI/litellm"
    ]
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []
    seen_repos = set()
    found_count = 0

    for _, row in df.iterrows():
        # Stop once we hit the limit
        if found_count >= SCAN_LIMIT:
            break

        repo = row['repo_name']
        
        # SKIP LOGIC: Check against exclude list
        if repo in EXCLUDE_REPOS:
            continue

        num = str(row['number'])
        lang = row['primary_language']
        agent = row['agent_name']
        title = row.get('title', 'Untitled')

        # Avoid scanning the same repo twice in one run
        if repo in seen_repos:
            continue

        # Check PR size before adding to matrix
        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res and lines_res.returncode == 0:
            stats = json.loads(lines_res.stdout)
            total_changes = stats.get("additions", 0) + stats.get("deletions", 0)
            if total_changes > MAX_PR_LINES:
                print(f"Skipping {repo} #{num}: Too large ({total_changes} lines)")
                continue
        else:
            print(f"Skipping {repo} #{num}: PR data inaccessible")
            continue

        # Format data for GitHub Actions Matrix
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

    # Output to GitHub Actions environment
    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        # For local testing
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
