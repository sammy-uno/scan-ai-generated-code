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
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 1000 
    
    # 🧪 TEST CRITERIA: Process exactly 2 PRs per batch to safely verify the loop logic
    SCAN_LIMIT = 2     
    
    try:
        chunk_offset = int(os.environ.get('CHUNK_OFFSET', '0'))
    except ValueError:
        chunk_offset = 0

    EXCLUDE_REPOS = ["BerriAI/litellm", "elastic/kibana", "tinygrad/tinygrad", "classmethod/tsumiki", "camunda/camunda", "Azure/azure-sdk-for-python", "wzdavid/ThinkRAG"]
    stats = {"added": 0, "too_big": 0, "excluded": 0, "api_error": 0, "duplicates": 0, "empty": 0, "skipped_by_offset": 0}
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []
    seen_repos = set()
    processed_count = 0

    print(f"--- Starting TEST Discovery (Offset: {chunk_offset} | Target: {SCAN_LIMIT} PRs) ---")
    for _, row in df.iterrows():
        if len(matrix_include) >= SCAN_LIMIT: 
            break
        
        repo = row['repo_name']
        num = str(row['number'])
        title = str(row['title'])
        lang = str(row['primary_language'])
        agent = str(row['agent_name'])
        
        if processed_count < chunk_offset:
            processed_count += 1
            stats["skipped_by_offset"] += 1
            continue
            
        processed_count += 1

        if repo in EXCLUDE_REPOS:
            stats["excluded"] += 1
            continue
        if repo in seen_repos:
            stats["duplicates"] += 1
            continue
            
        seen_repos.add(repo)
        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res: 
            data = json.loads(lines_res.stdout)
            total = data.get("additions", 0) + data.get("deletions", 0)
            
            if total == 0:
                stats["empty"] += 1
                continue
            if total > MAX_PR_LINES:
                stats["too_big"] += 1
                continue
        else:
            stats["api_error"] += 1
            continue

        matrix_include.append({
            "pr_num": num, 
            "repo_name": repo, 
            "language": lang, 
            "pr_title": title, 
            "agent_name": agent,
            "category_name": f"{repo.replace('/', '_SLASH_')}--{num}--{lang}--{agent.replace(' ', '_')}"
        })
        stats["added"] += 1

    next_offset = chunk_offset + len(matrix_include) + stats["too_big"] + stats["empty"] + stats["excluded"] + stats["duplicates"] + stats["api_error"]
    has_more_data = "true" if next_offset < len(df) and stats["added"] > 0 else "false"

    print("\n--- TEST Discovery Summary ---")
    print(f"✅ Total Added to Matrix: {stats['added']}")
    print(f"⏩ Skipped by Offset:    {stats['skipped_by_offset']}")
    print(f"🔢 Next Pointer Offset:   {next_offset}")
    print(f"🔄 Continues Remaining:   {has_more_data}")
    print("-------------------------\n")

    output = json.dumps({"include": matrix_include})
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f: 
            f.write(f'matrix_data={output}\n')
            f.write(f'next_offset={next_offset}\n')
            f.write(f'has_more_data={has_more_data}\n')
    else: 
        print(f"matrix_data={output}")

if __name__ == '__main__': 
    main()
