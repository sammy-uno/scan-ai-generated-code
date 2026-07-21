import json
import os
import subprocess
import sys

def get_pr_changed_files_list():
    """
    🎯 LOCAL WORKSPACE FILE STRIPPER: Ignores line hunk offsets completely.
    Grabs a clean list of every base filename touched or modified by the PR.
    """
    changed_filenames = set()  # Stores base names like 'models.py', 'index.ts'
    try:
        print("\n====================================================")
        print("📥 LOCAL WORKSPACE TRACE: CAPTURING MODIFIED FILENAMES")
        print("====================================================")
        
        # Pull every file name changed in the active PR branch commit footprint
        cmd = "git diff --name-only HEAD~1 HEAD"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
        
        if res.returncode != 0 or not res.stdout.strip():
            cmd = "git diff --name-only origin/main...HEAD"
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
            
        if res.returncode != 0:
            print(f"⚠️ Local Workspace Git Query Warning code: {res.returncode}")
            return changed_filenames
            
        for line in res.stdout.split('\n'):
            clean_line = line.strip()
            if clean_line:
                base_name = os.path.basename(clean_line)
                changed_filenames.add(base_name)
                print(f"✅ [GIT FILE TRACE] Target file detected: {clean_line} (Base: {base_name})")
                
        print("====================================================\n")
                    
    except Exception as e:
        print(f"❌ [CRITICAL] Error parsing workspace filename map context: {e}")
    return changed_filenames

def main():
    sarif_path = "results.sarif"
    if not os.path.exists(sarif_path):
        return
        
    try:
        with open(sarif_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return

    runs = data.get('runs', [])
    if not runs or not isinstance(runs, list):
        return

    repo = os.environ.get('PR_REPO', '')
    pr_num = os.environ.get('PR_NUM', '')
    pr_loc = int(os.environ.get('PR_LOC', '1'))

    print(f"📋 [DEBUG ENVIRONMENT] Repo: {repo} | PR Num: {pr_num} | Declared Size: {pr_loc} LOC")

    # Fetch the exact file basenames modified by the agent
    pr_changed_files = get_pr_changed_files_list()
    print(f"🔍 [TRACE MASTER MATRIX] Final Complete PR File Change Keys: {list(pr_changed_files)}")
        
    # --- BULLETPROOF CWE EXTRACTOR ---
    cwe_map = {}
    try:
        all_rules = []
        for run in runs:
            if not isinstance(run, dict): continue
            tool = run.get('tool', {})
            all_rules.extend(tool.get('driver', {}).get('rules', []))
            extensions = tool.get('extensions', [])
            if isinstance(extensions, list):
                for ext in extensions:
                    if isinstance(ext, dict): 
                        all_rules.extend(ext.get('rules', []))

        for rule in all_rules:
            if not isinstance(rule, dict): continue
            rule_id = rule.get('id')
            if not rule_id: continue
            tags = rule.get('properties', {}).get('tags', [])
            if rule_id not in cwe_map: 
                cwe_map[rule_id] = set()
            for tag in tags:
                if isinstance(tag, str) and 'cwe-' in tag.lower():
                    cwe_num = tag.lower().split('cwe-')[-1].zfill(3)
                    cwe_map[rule_id].add(f"CWE-{cwe_num}".upper())
    except Exception as e:
        print(f"Metadata mapping warning: {e}")

    # --- AGGREGATE RESULTS & FILTER BY PR FILENAMES ---
    consolidated_results = []
    seen_findings = set()

    print("\n====================================================")
    print("🎯 DEBUG LOG STEP 2: EVALUATING INDIVIDUAL SARIF ALERTS")
    print("====================================================")

    total_raw_alerts_processed = 0
    for run in runs:
        if not isinstance(run, dict): continue
        results = run.get('results', [])
        if not isinstance(results, list): continue
        
        for res in results:
            if not isinstance(res, dict): continue
            total_raw_alerts_processed += 1
            rule_id = res.get('ruleId', 'Unknown')
            locs_arr = res.get('locations', [])
            
            primary_path = "Unknown"
            primary_line = "?"
            
            if isinstance(locs_arr, list) and len(locs_arr) > 0:
                loc_entry = locs_arr[0]
                if isinstance(loc_entry, dict):
                    locs = loc_entry.get('physicalLocation', {})
                    if isinstance(locs, dict):
                        primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown').strip()
                        primary_line = locs.get('region', {}).get('startLine', '?')

            # 🚀 BASE NAME PASS FILTER: Check if the base file name matches any file touched in the PR
            if pr_changed_files:
                alert_base_name = os.path.basename(primary_path)
                if alert_base_name not in pr_changed_files:
                    print(f"❌ [FILTERED OUT] Alert `{rule_id}` at `{primary_path}:{primary_line}` -> File name '{alert_base_name}' not in PR changes list.")
                    continue
                
                print(f"🟢 [KEEP ALERT] Alert `{rule_id}` at `{primary_path}:{primary_line}` matches modified file '{alert_base_name}'!")

            fingerprint = f"{rule_id}::{primary_path}::{primary_line}"
            if fingerprint not in seen_findings:
                seen_findings.add(fingerprint)
                res['_primary_path'] = primary_path
                res['_primary_line'] = primary_line
                consolidated_results.append(res)

    print(f"\n📊 [SUMMARY CHECK] Scanned {total_raw_alerts_processed} raw alerts -> Isolated {len(consolidated_results)} pure PR introduced vulnerabilities.")
    print("====================================================\n")

    # Overwrite results.sarif with only the filtered findings
    if consolidated_results:
        for run in runs:
            if isinstance(run, dict) and 'results' in run:
                run['results'] = consolidated_results
        with open(sarif_path, 'w') as f:
            json.dump(data, f)
    else:
        for run in runs:
            if isinstance(run, dict) and 'results' in run:
                run['results'] = []
        with open(sarif_path, 'w') as f:
            json.dump(data, f)

    summary_md = f"\n### 🛡️ Analysis Details: {len(consolidated_results)} PR-Introduced Issues Found (PR Size: {pr_loc} LOC)\n"
    
    if consolidated_results:
        cwe_per_loc = round(len(consolidated_results) / pr_loc, 4) if pr_loc > 0 else 0.0
        summary_md += f"**PR Code Change CWE Density:** {cwe_per_loc} Issues per Line of Code (LOC)\n\n"
        summary_md += "| Severity | CWE | Vulnerability | File:Line | Description |\n| :--- | :--- | :--- | :--- | :--- |\n"
        
        CWE_TOP_25 = [
            'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
            'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
            'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
            'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
        ]
        
        for res in consolidated_results:
            path = res.get('_primary_path', 'Unknown')
            line = res.get('_primary_line', '?')
            level = res.get('level', 'warning')
            rule_id = res.get('ruleId', 'Unknown')
            
            cwes_set = cwe_map.get(rule_id, set())
            cwe_display = ", ".join(sorted(list(cwes_set))) if cwes_set else "N/A"
            is_top_25 = any(c in CWE_TOP_25 for c in cwes_set)
            
            icon_display = "🔴 High" if (level == 'error' or is_top_25) else ("🟡 Medium" if level == 'warning' else "🔵 Low")
            
            raw_msg = res.get('message', {}).get('text', 'No description')
            if isinstance(raw_msg, str):
                msg = raw_msg.split('\n')[0] if '\n' in raw_msg else raw_msg
            else:
                msg = "No description details provided."
                
            msg = msg.replace('|', '\\|')
            
            summary_md += f"| {icon_display} | **{cwe_display}** | `{rule_id}` | `{path}:{line}` | {msg} |\n"

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'a') as f: 
        f.write(summary_md)

if __name__ == "__main__":
    main()
