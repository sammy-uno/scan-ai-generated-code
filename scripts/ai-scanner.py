import subprocess, json, os, time, pandas as pd

def run_command(command, max_retries=2):
    for attempt in range(max_retries):
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=30)
            if result.returncode == 0: 
                return result
            time.sleep(1)
        except subprocess.TimeoutExpired: 
            continue
    return None

def main():
    # --- CONFIGURATION (TARGET FIXED TO 20 RUNS) ---
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 1000 
    SCAN_LIMIT = 500     # Corrected to match architecture requirement
    EXCLUDE_REPOS = ["BerriAI/litellm", "elastic/kibana", "tinygrad/tinygrad"]
    
    # --- TRACKING ---
    stats = {"added": 0, "too_big": 0, "excluded": 0, "api_error": 0, "duplicates": 0, "empty": 0}
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []
    seen_repos = set()

    print(f"--- Starting Discovery (Target: {SCAN_LIMIT} PRs) ---")
    for _, row in df.iterrows():
        if stats["added"] >= SCAN_LIMIT: 
            break
        
        # 🚀 RESTORED ORIGINAL CSV HEADERS
        repo = row['repo_name']
        num = str(row['number'])
        title = str(row['title'])
        lang = str(row['primary_language'])
        agent = str(row['agent_name'])
        stars = str(row['repo_stars'])
        
        if repo in EXCLUDE_REPOS:
            print(f"SKIP: {repo} (Manual Exclude)")
            stats["excluded"] += 1
            continue

        if repo in seen_repos:
            print(f"SKIP: {repo} #{num} (Duplicate Repo Filtered)")
            stats["duplicates"] += 1
            continue
            
        # Immediately track to prevent duplicate API hammering
        seen_repos.add(repo)
        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res: 
            data = json.loads(lines_res.stdout)
            total = data.get("additions", 0) + data.get("deletions", 0)
            
            # 🚀 ZERO-CHANGE EXCLUSION GUARD:
            # Drops any PR that has 0 modifications
            if total == 0:
                print(f"SKIP: {repo} #{num} (Empty PR: 0 files/lines change)")
                stats["empty"] += 1
                continue
                
            if total > MAX_PR_LINES:
                print(f"SKIP: {repo} #{num} (Size: {total} lines)")
                stats["too_big"] += 1
                continue
        else:
            print(f"SKIP: {repo} #{num} (API/Access Error)")
            stats["api_error"] += 1
            continue

        # 🚀 RESTORED ORIGINAL WORKFLOW MATRIX SCHEME
        matrix_include.append({
            "pr_num": num, 
            "repo_name": repo, 
            "language": lang, 
            "pr_title": title, 
            "agent_name": agent,
            "category_name": f"{repo.replace('/', '_SLASH_')}--{num}--{lang}--{agent.replace(' ', '_')}"
        })
        
        print(f"ADDED: {repo} #{num} ({total} lines)")
        stats["added"] += 1

    print("\n--- Discovery Summary ---")
    print(f"✅ Total Added to Matrix: {stats['added']}")
    print(f"❌ Skipped (Too Large):   {stats['too_big']}")
    print(f"💨 Skipped (Empty 0 LOC):  {stats['empty']}")
    print(f"🚫 Skipped (Excluded):    {stats['excluded']}")
    print(f"👯 Skipped (Duplicates):  {stats['duplicates']}")
    print(f"⚠️  Skipped (API Errors): {stats['api_error']}")
    print("-------------------------\n")

    output = json.dumps({"include": matrix_include})
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f: 
            f.write(f'matrix_data={output}\n')
    else: 
        print(f"matrix_data={output}")

if __name__ == '__main__': 
    main()
