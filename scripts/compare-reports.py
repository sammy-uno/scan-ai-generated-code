import json
import glob
import os
import subprocess
from datetime import datetime, timedelta

def get_pr_changed_lines_compare(repo, pr_num):
    """
    🎯 COMPARISON TRACKER FILTER: Queries the stable files endpoint directly during 
    the master comparison phase to isolate base filenames touched by the PR.
    """
    changed_lines = {}
    if not repo or not pr_num:
        return changed_lines
    try:
        cmd = f"gh pr view {pr_num} --repo {repo} --json files"
        sub_env = os.environ.copy()
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15, env=sub_env)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            files = data.get('files', [])
            for f in files:
                path = f.get('path', '').strip()
                if path:
                    changed_lines[path] = set()
    except Exception as e:
        print(f"Comparison asset tracking notice: {e}")
    return changed_lines

def main():
    search_path = os.path.join('all-results', '**', '*.sarif')
    all_files = sorted(glob.glob(search_path, recursive=True)) if os.path.exists('all-results') else []
    
    # Extended metrics tracking dict architecture to handle low indices and lifecycle breakdowns
    ai_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "open": 0, "closed": 0, "merged": 0, "total_loc": 0}
    human_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "open": 0, "closed": 0, "merged": 0, "total_loc": 0}
    
    CWE_TOP_25 = [
        'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
        'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
        'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
        'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
    ]

    has_agent_vulnerability_registered = False
    latest_ai_epoch = 0.0
    latest_human_epoch = 0.0

    # Track processed keys dynamically to avoid duplicate count mutations
    seen_prs = set()

    for f in all_files:
        fname = os.path.basename(f)
        parent_dir = os.path.basename(os.path.dirname(f))
        
        repo_path = ""
        pr_num = ""
        live_loc = 100
        is_human = False

        # 🚀 100% GENERIC METADATA EXTRACTION:
        # Extracts all properties dynamically from the file or parent directory tokens
        if '--' in fname or '--' in parent_dir:
            naming_string = fname.replace('.sarif', '') if '--' in fname else parent_dir.replace('sarif-', '')
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

        # If a file does not match your standardized double-dash research token layout, skip it
        if not repo_path or not pr_num:
            continue

        try:
            f_mtime = os.path.getmtime(f)
            if is_human:
                if f_mtime > latest_human_epoch: latest_human_epoch = f_mtime
            else:
                if f_mtime > latest_ai_epoch: latest_ai_epoch = f_mtime

            pr_diff_map = get_pr_changed_lines_compare(repo_path, pr_num)

            with open(f, 'r', encoding='utf-8') as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list) or len(runs) == 0: 
                continue
            
            res = []
            seen_findings = set()
            local_cwe_map = {}
            
            for run in runs:
                if not isinstance(run, dict): continue
                tool = run.get('tool', {})
                all_rules = tool.get('driver', {}).get('rules', [])
                extensions = tool.get('extensions', [])
                if isinstance(extensions, list):
                    for ext in extensions:
                        if isinstance(ext, dict): all_rules.extend(ext.get('rules', []))
                
                for rule in all_rules:
                    if not isinstance(rule, dict): continue
                    r_id = rule.get('id')
                    tags = rule.get('properties', {}).get('tags', [])
                    if r_id not in local_cwe_map: local_cwe_map[r_id] = set()
                    for t in tags:
                        if isinstance(t, str) and 'cwe-' in t.lower():
                            c_num = t.lower().split('cwe-')[-1].zfill(3)
                            local_cwe_map[r_id].add(f'CWE-{c_num}'.upper())

            for run in runs:
                if not isinstance(run, dict): continue
                results = run.get('results', [])
                if not isinstance(results, list): continue
                
                for result in results:
                    if not isinstance(result, dict): continue
                    rule_id = result.get('ruleId', 'Unknown')
                    locs_arr = result.get('locations', [])
                    
                    primary_path = "Unknown"
                    if isinstance(locs_arr, list) and len(locs_arr) > 0:
                        loc_entry = locs_arr[0]
                        if isinstance(loc_entry, dict):
                            locs = loc_entry.get('physicalLocation', {})
                            if isinstance(locs, dict):
                                primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown').strip()
                                
                    if pr_diff_map:
                        alert_base = os.path.basename(primary_path).lower()
                        changed_bases = [os.path.basename(p).lower() for p in pr_diff_map.keys()]
                        if alert_base not in changed_bases: continue

                    fingerprint = f'{rule_id}::{primary_path}'
                    if fingerprint not in seen_findings:
                        seen_findings.add(fingerprint)
                        res.append(result)

            h, m, l = 0, 0, 0
            for r in res:
                cwes_for_rule = local_cwe_map.get(r.get('ruleId', ''), set())
                level_str = str(r.get('level', 'warning')).lower()
                
                if any(c in CWE_TOP_25 for c in cwes_for_rule) or level_str == 'error': 
                    h += 1
                elif level_str in ['warning', 'recommendation', 'note', 'none']: 
                    m += 1
                    if not is_human: has_agent_vulnerability_registered = True
                else: 
                    l += 1

            target = human_metrics if is_human else ai_metrics
            target["total"] += len(res)
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
            print(f"Error evaluating comparison artifact: {e}")

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
    # This forces the comparison engine to print the exact metrics it calculated
    # straight into your GitHub Actions step logs so you can audit it in real time!
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
