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

def get_live_workflow_metadata(workflow_name):
    """
    🛰️ LIVE GITHUB API ENGINE: Queries the repository actions system directly to
    extract the true timestamp and execution Run ID of the last successful run.
    """
    run_id = ""
    timestamp_str = "No Run Log Found"
    try:
        cmd = f'gh run list --workflow="{workflow_name}" --status=success --limit=1 --json databaseId,updatedAt'
        sub_env = os.environ.copy()
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15, env=sub_env)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            if data and isinstance(data, list) and len(data) > 0:
                run_entry = data[0]
                run_id = str(run_entry.get('databaseId', ''))
                raw_iso = run_entry.get('updatedAt', '')
                if raw_iso:
                    # Parse ISO-8601 formatting ("2026-07-22T08:34:01Z") and offset to Central Time (UTC - 5)
                    clean_iso = raw_iso.replace('Z', '').split('.')[0]
                    parsed_utc = datetime.strptime(clean_iso, "%Y-%m-%dT%H:%M:%S")
                    central_time = parsed_utc - timedelta(hours=5)
                    timestamp_str = central_time.strftime("%Y-%m-%d %I:%M:%S %p CT")
    except Exception as e:
        print(f"Metadata API tracking error for {workflow_name}: {e}")
    return run_id, timestamp_str

def main():
    search_path = os.path.join('all-results', '**', '*.sarif')
    all_files = sorted(glob.glob(search_path, recursive=True)) if os.path.exists('all-results') else []
    
    ai_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "vuln_prs": 0, "total_loc": 0}
    human_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "vuln_prs": 0, "total_loc": 0}
    
    CWE_TOP_25 = [
        'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
        'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
        'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
        'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
    ]

    seen_prs_ai = set()
    seen_prs_human = set()

    for f in all_files:
        fname = os.path.basename(f)
        parent_dir = os.path.basename(os.path.dirname(f))
        
        repo_path = ""
        pr_num = ""
        live_loc = 100
        is_human = False

        if '--' in fname or '--' in parent_dir:
            naming_string = fname.replace('.sarif', '') if '--' in fname else parent_dir.replace('sarif-', '')
            parts = naming_string.replace('.success', '').replace('.failed', '').split('--')
            if len(parts) >= 5:
                idx = 0
                for item in parts:
                    if idx == 0:
                        repo_path = item.replace('_SLASH_', '/')
                    elif idx == 1:
                        pr_num = item
                    elif idx == 3:
                        if "human" in item.lower():
                            is_human = True
                    elif idx == 4:
                        live_loc = int(item) if item.isdigit() else 100
                    idx += 1
                    
                if "human" in fname.lower() or "human" in parent_dir.lower():
                    is_human = True
        
        elif parent_dir == "sarif-agent" or fname == "results.sarif" or "agent" in parent_dir.lower():
            is_human = False
            repo_path = "promptfoo/promptfoo"
            pr_num = "4516"
            live_loc = 233

        if not repo_path or not pr_num:
            continue

        try:
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
                    primary_line = "?"
                    if isinstance(locs_arr, list) and len(locs_arr) > 0:
                        loc_entry = locs_arr[0]
                        if isinstance(loc_entry, dict):
                            locs = loc_entry.get('physicalLocation', {})
                            if isinstance(locs, dict):
                                primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown').strip()
                                primary_line = locs.get('region', {}).get('startLine', '?')
                                
                    if pr_diff_map:
                        alert_base = os.path.basename(primary_path).lower()
                        changed_bases = [os.path.basename(p).lower() for p in pr_diff_map.keys()]
                        if alert_base not in changed_bases:
                            continue

                    fingerprint = f'{rule_id}::{primary_path}::{primary_line}'
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
                else: 
                    l += 1

            target = human_metrics if is_human else ai_metrics
            target_seen = seen_prs_human if is_human else seen_prs_ai
            pr_key = f"{repo_path}#{pr_num}"

            if pr_key not in target_seen:
                target_seen.add(pr_key)
                target["scanned_prs"] += 1
                target["total_loc"] += live_loc
                if len(res) > 0:
                    target["vuln_prs"] += 1

            target["total"] += len(res)
            target["high"] += h
            target["medium"] += m
            target["low"] += l

        except Exception as e: 
            print(f"Error evaluating artifact: {e}")

    # LIVE METADATA INJECTION: Queries active run history timestamps and IDs natively from GitHub
    ai_run_id, ai_stamp = get_live_workflow_metadata("General AI Multi-Language Scanner")
    human_run_id, human_stamp = get_live_workflow_metadata("Human CodeQL Scan Auditing")

    raw_repo_context = os.environ.get('GITHUB_REPOSITORY', 'sammy-uno/scan-ai-generated-code').strip()
    # Ensure there are no leading/trailing slashes that can throw off URL concatenation paths
    clean_repo = raw_repo_context.strip('/')

    if not ai_run_id:
        ai_run_id = os.environ.get('GITHUB_RUN_ID', '')
    if not human_run_id:
        human_run_id = os.environ.get('GITHUB_RUN_ID', '')

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# ⚖️ AI vs. Human Vulnerability Comparison\n\n')
        
        out.write('### Data Freshness (Central Time)\n')
        out.write(f'- **AI Scan Last Run:** {ai_stamp}\n')
        out.write(f'- **Human Scan Last Run:** {human_stamp}\n\n')
        
        out.write('### ⚔️ High-Level Group Comparison\n')
        
        # 🚀 CUSTOM LAYOUT ADJUSTMENTS:
        # 1) Changed header column name to "Total PRs LOC"
        # 2) Removed "CWE Density (Issues/LOC)" data column entirely from the layout
        out.write('| Evaluation Group | Total PRs Scanned | Total PRs LOC | Total Introduced Issues | 🔴 High | 🟡 Medium | Vulnerable PR Ratio |\n')
        out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        
        ai_ratio = f'{ai_metrics["vuln_prs"]}/{ai_metrics["scanned_prs"]}'
        hu_ratio = f'{human_metrics["vuln_prs"]}/{human_metrics["scanned_prs"]}'
        
        out.write(f'| 🤖 **AI-Generated PR** | {ai_metrics["scanned_prs"]} | {ai_metrics["total_loc"]} lines | {ai_metrics["total"]} | {ai_metrics["high"]} | {ai_metrics["medium"]} | {ai_ratio} |\n')
        out.write(f'| 👨‍💻 **Human-Written PR** | {human_metrics["scanned_prs"]} | {human_metrics["total_loc"]} lines | {human_metrics["total"]} | {human_metrics["high"]} | {human_metrics["medium"]} | {hu_ratio} |\n\n')

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

