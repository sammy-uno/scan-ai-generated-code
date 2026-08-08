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
    # --- CONFIGURATION ---
    INPUT_CSV = "aidev_scan_list.csv"
    MAX_PR_LINES = 1000 
    SCAN_LIMIT = 5     # Scaled ceiling capacity allocation bounds
    
    # 🚀 CHUNK OFFSET INGESTION LAYER
    try:
        chunk_offset = int(os.environ.get('CHUNK_OFFSET', '0'))
    except ValueError:
        chunk_offset = 0
    
    # --- TRACKING ---
    stats = {"added": 0, "too_big": 0, "excluded": 0, "api_error": 0, "duplicates": 0, "empty": 0}
    EXCLUDE_REPOS = ["BerriAI/litellm", "elastic/kibana", "tinygrad/tinygrad", "classmethod/tsumiki", "camunda/camunda", "Azure/azure-sdk-for-python", "wzdavid/ThinkRAG", "Azure/azure-sdk-for-js", 
"typehero/typehero", "ruvnet/claude-flow"]
    
    if not os.path.exists(INPUT_CSV):
        print('matrix_data={"include":[]}')
        return

    df = pd.read_csv(INPUT_CSV)
    matrix_include = []
    
    # 🚀 THE HARDENED RESET FILTER LAYER:
    # Only load previous memory records if the offset pointer is greater than 0.
    # If the user starts at 0, ignore any hidden cached files to force a clean pass from the top!
    seen_repos = set()
    accumulated_db_path = "all-results/accumulated_database.json"
    
    if chunk_offset > 0 and os.path.exists(accumulated_db_path):
        try:
            with open(accumulated_db_path, "r", encoding="utf-8") as db_f:
                historical_rows = json.load(db_f)
                if isinstance(historical_rows, list):
                    for r in historical_rows:
                        hist_repo = r.get('repo', '').strip()
                        if hist_repo:
                            seen_repos.add(hist_repo)
                    print(f"📥 [CROSS-BATCH SNAPSHOT LOADED] Pre-loaded {len(seen_repos)} unique repositories from master database memory.")
        except Exception as cache_err:
            print(f"⚠️ Warning: Could not hydrate cross-batch deduplication memory: {cache_err}")
    else:
        print("🧼 [CLEAN INITIAL PASS] Offset is 0. Discarding all cross-batch data caches to start fresh from row 1.")

    processed_count = 0

    print(f"--- Starting Discovery (Offset: {chunk_offset} | Target Limit: {SCAN_LIMIT} PRs) ---")
    for _, row in df.iterrows():
        # Stop building the active chunk once we hit our max concurrent runner matrix ceiling
        if stats["added"] >= SCAN_LIMIT: 
            break
        
        # 🚀 CHUNK GUARD CONTEXT SLICER
        # Skips rows belonging to previous batch execution runs
        if processed_count < chunk_offset:
            processed_count += 1
            continue
            
        processed_count += 1
        
        repo = row['repo_name']
        num = str(row['number'])
        title = str(row['title'])
        lang = str(row['primary_language'])
        agent = str(row['agent_name'])
        
        if repo in EXCLUDE_REPOS:
            print(f"SKIP: {repo} (Manual Exclude)")
            stats["excluded"] += 1
            continue

        # 🚀 ACTIVATED CROSS-BATCH DEDUPLICATION FILTER
        if repo in seen_repos:
            print(f"SKIP: {repo} #{num} (Duplicate Repo Filtered Natively across historical batches)")
            stats["duplicates"] += 1
            continue
            
        # Track immediately to block duplicates inside the current fanned execution row loop
        seen_repos.add(repo)
        
        lines_res = run_command(f'gh pr view {num} --repo {repo} --json additions,deletions')
        if lines_res: 
            data = json.loads(lines_res.stdout)
            total = data.get("additions", 0) + data.get("deletions", 0)
            
            # ZERO-CHANGE EXCLUSION GUARD: Drops any PR that has 0 modifications
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

    # 🚀 ACCURATE POINTER BOUNDARY ARITHMETIC
    next_offset = chunk_offset + len(matrix_include) + stats["too_big"] + stats["empty"] + stats["excluded"] + stats["duplicates"] + stats["api_error"]
    has_more_data = "true" if next_offset < len(df) and stats["added"] > 0 else "false"
    #has_more_data = "false"

    #if chunk_offset < 3:
    #    has_more_data = "true"
    #    print(f"🧪 [TEST MODE] PR #{chunk_offset + 1} complete. Chaining next chunk at offset: {next_offset}")
    #else:
    #    has_more_data = "false"
    #    print(f"🧪 [TEST MODE] Final PR #{chunk_offset + 1} complete. Terminating the 4-pass test chain.")

    print("\n--- Discovery Summary ---")
    print(f"✅ Total Added to Matrix: {stats['added']}")
    print(f"❌ Skipped (Too Large):   {stats['too_big']}")
    print(f"💨 Skipped (Empty 0 LOC):  {stats['empty']}")
    print(f"🚫 Skipped (Excluded):    {stats['excluded']}")
    print(f"👯 Skipped (Duplicates):  {stats['duplicates']}")
    print(f"⚠️  Skipped (API Errors): {stats['api_error']}")
    print(f"🔢 Next Pointer Offset:   {next_offset}")
    print(f"🔄 Continues Remaining:   {has_more_data}")
    print("-------------------------\n")

    output = json.dumps({"include": matrix_include})
    
    # 🚀 EXPORT SIGNAL METRICS DIRECTLY TO JOB CONTEXT BOUNDARIES
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f: 
            f.write(f'matrix_data={output}\n')
            f.write(f'next_offset={next_offset}\n')
            f.write(f'has_more_data={has_more_data}\n')
    else: 
        print(f"matrix_data={output}")

if __name__ == '__main__': 
    main()
