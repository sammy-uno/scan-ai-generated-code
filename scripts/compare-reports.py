import json
import glob
import os
import subprocess
from datetime import datetime, timedelta

def main():
    # 🚀 THE FIX: Target the clean json summary tokens exclusively!
    search_path = os.path.join('all-results', '**', '*.json')
    all_files = sorted(glob.glob(search_path, recursive=True)) if os.path.exists('all-results') else []
    
    # Standard thesis metrics dictionary tracking buffers
    ai_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "open": 0, "closed": 0, "merged": 0, "total_loc": 0}
    human_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "open": 0, "closed": 0, "merged": 0, "total_loc": 0}
    
    latest_ai_epoch = 0.0
    latest_human_epoch = 0.0
    seen_prs = set()

    print("\n====================================================")
    print("🎯 COMPARATIVE TRACE STEP 1: PARSING SCORED JSON SUMMARIES")
    print("====================================================")

    for f in all_files:
        fname = os.path.basename(f)
        parent_dir = os.path.basename(os.path.dirname(f))
        
        # Skip standard system files if they drop into the folder root
        if fname == "summary.json":
            continue

        repo_path = ""
        pr_num = ""
        live_loc = 100
        is_human = False

        # Extract metadata from token handles natively
        if '--' in fname or '--' in parent_dir:
            naming_string = fname.replace('.json', '') if '--' in fname else parent_dir.replace('sarif-', '')
            parts = naming_string.replace('.success', '').replace('.failed', '').split('--')
            if len(parts) >= 5:
                idx = 0
                for item in parts:
                    if idx == 0: repo_path = item.replace('_SLASH_', '/')
                    elif idx == 1: pr_num = item
                    elif idx == 3:
                        if "human" in item.lower(): is_human = True
                    elif idx == 4: live_loc = int(item) if item.isdigit() else 100
                    idx += 1
                if "human" in fname.lower() or "human" in parent_dir.lower():
                    is_human = True

        if not repo_path or not pr_num:
            continue

        try:
            f_mtime = os.path.getmtime(f)
            if is_human:
                if f_mtime > latest_human_epoch: latest_human_epoch = f_mtime
            else:
                if f_mtime > latest_ai_epoch: latest_ai_epoch = f_mtime

            # 🚀 THE CRITICAL FIX: Extract metrics directly from our pre-filtered JSON summary files!
            with open(f, 'r', encoding='utf-8') as s:
                summary_data = json.load(s)

            h = int(summary_data.get('high', summary_data.get('H', 0)))
            m = int(summary_data.get('medium', summary_data.get('M', 0)))
            l = int(summary_data.get('low', summary_data.get('L', 0)))
            total_issues = int(summary_data.get('total_issues', summary_data.get('issues', h + m + l)))

            # 🔬 ADDED VERBOSE PERFORMANCE LOG TRACER
            print(f"📈 [COMPILING SUMMARY] Track: {'HUMAN' if is_human else 'AI'} | Target: {repo_path} #{pr_num}")
            print(f"   └── Read Metrics: {total_issues} (🔴 H: {h} | 🟡 M: {m} | 🔵 L: {l})")

            target = human_metrics if is_human else ai_metrics
            target["total"] += total_issues
            target["high"] += h
            target["medium"] += m
            target["low"] += l

            pr_track_key = f"{'human' if is_human else 'ai'}--{repo_path}#{pr_num}"
            if pr_track_key not in seen_prs:
                seen_prs.add(pr_track_key)
                target["scanned_prs"] += 1
                target["total_loc"] += live_loc

                # Generic live lifecycle query check inside evaluation tracker
                try:
                    cmd_state = f"gh pr view {pr_num} --repo {repo_path} --json state"
                    res_state = subprocess.run(cmd_state, capture_output=True, text=True, shell=True, timeout=15)
                    if res_state.returncode == 0:
                        st_data = json.loads(res_state.stdout)
                        raw_st = str(st_data.get('state', 'CLOSED')).upper()
                        if raw_st == "MERGED": target["merged"] += 1
                        elif raw_st == "OPEN": target["open"] += 1
                        else: target["closed"] += 1
                    else:
                        target["merged"] += 1
                except Exception:
                    target["merged"] += 1

        except Exception as e: 
            print(f"Error evaluating comparison artifact JSON: {e}")

    # Calculate density metrics programmatically
    ai_density_loc = round(ai_metrics["total"] / ai_metrics["total_loc"], 5) if ai_metrics["total_loc"] > 0 else 0.0
    human_density_loc = round(human_metrics["total"] / human_metrics["total_loc"], 5) if human_metrics["total_loc"] > 0 else 0.0

    current_repo_context = os.environ.get('GITHUB_REPOSITORY', 'sammy-uno/scan-ai-generated-code').strip()
    clean_repo = current_repo_context.strip('/')
    
    # Initialize variables for live API lookups
    ai_run_id = ""
    ai_stamp = "No Run Log Found"
    human_run_id = ""
    human_stamp = "No Run Log Found"
    sub_env = os.environ.copy()

    # LIVE AI WORKFLOW LOG METADATA QUERY
    try:
        cmd_ai = 'gh run list --workflow="General AI Multi-Language Scanner" --status=success --limit=1 --json databaseId,updatedAt'
        res_ai = subprocess.run(cmd_ai, capture_output=True, text=True, shell=True, timeout=15, env=sub_env)
        if res_ai.returncode == 0:
            data_ai = json.loads(res_ai.stdout)
            if data_ai and isinstance(data_ai, list) and len(data_ai) > 0:
                run_entry = data_ai[0]
                ai_run_id = str(run_entry.get('databaseId', ''))
                raw_iso = run_entry.get('updatedAt', '')
                if raw_iso:
                    clean_iso = raw_iso.replace('Z', '').split('.')
                    parsed_utc = datetime.strptime(clean_iso[0], "%Y-%m-%dT%H:%M:%S")
                    central_time = parsed_utc - timedelta(hours=5)
                    ai_stamp = central_time.strftime("%Y-%m-%d %I:%M:%S %p CT")
    except Exception:
        pass

    # LIVE HUMAN WORKFLOW LOG METADATA QUERY
    try:
        cmd_hu = 'gh run list --workflow="Human CodeQL Scan Auditing" --status=success --limit=1 --json databaseId,updatedAt'
        res_hu = subprocess.run(cmd_hu, capture_output=True, text=True, shell=True, timeout=15, env=sub_env)
        if res_hu.returncode == 0:
            data_hu = json.loads(res_hu.stdout)
            if data_hu and isinstance(data_hu, list) and len(data_hu) > 0:
                run_entry = data_hu[0]
                human_run_id = str(run_entry.get('databaseId', ''))
                raw_iso = run_entry.get('updatedAt', '')
                if raw_iso:
                    clean_iso = raw_iso.replace('Z', '').split('.')
                    parsed_utc = datetime.strptime(clean_iso[0], "%Y-%m-%dT%H:%M:%S")
                    central_time = parsed_utc - timedelta(hours=5)
                    human_stamp = central_time.strftime("%Y-%m-%d %I:%M:%S %p CT")
    except Exception:
        pass

    # Dynamic fallback to current runner run context if API queries return empty strings
    if not ai_run_id:
        ai_run_id = os.environ.get('GITHUB_RUN_ID', '')
        ai_stamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p CT")
    if not human_run_id:
        human_run_id = os.environ.get('GITHUB_RUN_ID', '')
        human_stamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p CT")

    # 🔬 ACTIVE CONSOLE DIAGNOSTIC TRACE BLOCK:
    print("\n====================================================")
    print("📊 COMPARATIVE TRACE STEP 2: COMPILED EVALUATION GRID")
    print("====================================================")
    print(f" 🤖 AI Group Metrics -> Scanned PRs: {ai_metrics['scanned_prs']} | Introduced: {ai_metrics['total']} (🔴 H: {ai_metrics['high']} 🟡 M: {ai_metrics['medium']} 🔵 L: {ai_metrics['low']})")
    print(f" 👨‍💻 Human Group Metrics -> Scanned PRs: {human_metrics['scanned_prs']} | Introduced: {human_metrics['total']} (🔴 H: {human_metrics['high']} 🟡 M: {human_metrics['medium']} 🔵 L: {human_metrics['low']})")
    print("====================================================\n")

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# ⚖️ AI vs. Human Vulnerability Comparison\n\n')
        
        out.write('### Data Freshness (Central Time)\n')
        out.write(f'- **AI Scan Last Run:** {ai_stamp}\n')
        out.write(f'- **Human Scan Last Run:** {human_stamp}\n\n')
        
        out.write('### ⚔️ High-Level Group Comparison\n')
        
        # 🚀 COLUMN HEADING UPDATE: Enforces your exact title standard cleanly
        out.write('| Evaluation Group | Total PRs Scanned | Total PRs LOC | Total CWEs Introduced | 🔴 High | 🟡 Medium | 🔵 Low | Total PRs open | Total PRs closed | Total PRs merged |\n')
        out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        
        out.write(f'| 🤖 **AI-Generated PR** | {ai_metrics["scanned_prs"]} | {ai_metrics["total_loc"]} lines | {ai_metrics["total"]} | {ai_metrics["high"]} | {ai_metrics["medium"]} | {ai_metrics["low"]} | {ai_metrics["open"]} | {ai_metrics["closed"]} | {ai_metrics["merged"]} |\n')
        out.write(f'| 👨‍💻 **Human-Written PR** | {human_metrics["scanned_prs"]} | {human_metrics["total_loc"]} lines | {human_metrics["total"]} | {human_metrics["high"]} | {human_metrics["medium"]} | {human_metrics["low"]} | {human_metrics["open"]} | {human_metrics["closed"]} | {human_metrics["merged"]} |\n\n')

        out.write('### 🔗 Detailed Actions Summaries\n')
        base_domain = "https://github.com"
        
        if ai_run_id:
            full_ai_url = f"{base_domain}/{clean_repo}/actions/runs/{ai_run_id}"
            out.write(f'- 🤖 **View Detailed AI Scanner Workflow Summary:** Go to Actions Run [#{ai_run_id}]({full_ai_url}) 🔍\n')
        else:
            out.write('- 🤖 **View Detailed AI Scanner Workflow Summary:** Check repository Actions panel history profiles. 🔍\n')
            
        if human_run_id:
            full_human_url = f"{base_domain}/{clean_repo}/actions/runs/{human_run_id}"
            out.write(f'- 👨‍💻 **View Detailed Human Auditor Workflow Summary:** Go to Actions Run [#{human_run_id}]({full_human_url}) 🔍\n')
        else:
            out.write('- 👨‍💻 **View Detailed Human Auditor Workflow Summary:** Check repository Actions panel history profiles. 🔍\n')

if __name__ == "__main__": 
    main()
