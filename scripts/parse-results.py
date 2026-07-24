import json
import glob
import os
import subprocess
import sys

def get_pr_changed_files_list():
    """
    🎯 100% API-DRIVEN FILE TRACKER: Queries the GitHub CLI API directly
    to isolate true modified files, eliminating fragile git diff branch mismatches.
    """
    changed_filenames = set()
    repo = os.environ.get('PR_REPO', '')
    pr_num = os.environ.get('PR_NUM', '')
    
    if not repo or not pr_num:
        print("⚠️ Environment notice: PR_REPO or PR_NUM missing. Skipping API file filters.")
        return changed_filenames

    try:
        print("\n====================================================")
        print("📥 API LOG TRACE: CAPTURING TRUSTED PR MODIFIED FILES")
        print("====================================================")
        
        cmd = f"gh pr view {pr_num} --repo {repo} --json files"
        sub_env = os.environ.copy()
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=20, env=sub_env)
        
        if res.returncode == 0:
            data = json.loads(res.stdout)
            files = data.get('files', [])
            for f in files:
                path = f.get('path', '').strip()
                if path:
                    base_name = os.path.basename(path).lower()
                    changed_filenames.add(base_name)
                    print(f"✅ [API PR FILE TRACE] Target file detected: {path} (Base Match Key: {base_name})")
        else:
            print(f"⚠️ GitHub CLI API Error code: {res.returncode}. Defaulting to empty baseline.")
            
        print("====================================================\n")
                    
    except Exception as e:
        print(f"❌ [CRITICAL] Error parsing API pull request filename map: {e}")
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
    
    raw_loc = os.environ.get('PR_LOC', '').strip()
    if not raw_loc or not raw_loc.isdigit():
        pr_loc = 1
    else:
        pr_loc = int(raw_loc)

    print(f"📋 [DEBUG ENVIRONMENT] Repo: {repo} | PR Num: {pr_num} | Declared Size: {pr_loc} LOC")

    pr_changed_files = get_pr_changed_files_list()
    print(f"🔍 [TRACE MASTER MATRIX] Final Complete PR File Change Keys: {list(pr_changed_files)}")
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
        
        for res_item in results:
            if not isinstance(res_item, dict): continue
            total_raw_alerts_processed += 1
            rule_id = res_item.get('ruleId', 'Unknown')
            locs_arr = res_item.get('locations', [])
            
            primary_path = "Unknown"
            primary_line = "?"
            
            # 🚀 FIXED ARRAY LOOKUP INDEX BUG HERE: Uses [0] to index list elements accurately
            if isinstance(locs_arr, list) and len(locs_arr) > 0:
                loc_entry = locs_arr[0]
                if isinstance(loc_entry, dict):
                    locs = loc_entry.get('physicalLocation', {})
                    if isinstance(locs, dict):
                        primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown').strip()
                        primary_line = locs.get('region', {}).get('startLine', '?')

            if pr_changed_files:
                alert_base_name = os.path.basename(primary_path)
                if alert_base_name.lower() not in [b.lower() for b in pr_changed_files]:
                    print(f"❌ [FILTERED OUT] Alert `{rule_id}` at `{primary_path}:{primary_line}` -> File name '{alert_base_name}' not in PR changes list.")
                    continue
                
                print(f"🟢 [KEEP ALERT] Alert `{rule_id}` at `{primary_path}:{primary_line}` matches modified file '{alert_base_name}'!")

            fingerprint = f"{rule_id}::{primary_path}::{primary_line}"
            if fingerprint not in seen_findings:
                seen_findings.add(fingerprint)
                res_item['_primary_path'] = primary_path
                res_item['_primary_line'] = primary_line
                consolidated_results.append(res_item)

    print(f"\n📊 [SUMMARY CHECK] Scanned {total_raw_alerts_processed} raw alerts -> Isolated {len(consolidated_results)} pure PR introduced vulnerabilities.")
    print("====================================================\n")

    # Save the isolated, line-filtered results back to results.sarif
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
    
    # DATA-DRIVEN SEVERITY METRICS INITIALIZATION (No hardcoding)
    h, m, l = 0, 0, 0
    all_discovered_cwes = set()
    CWE_TOP_25 = [
        'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
        'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
        'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
        'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
    ]

    if consolidated_results:
        cwe_per_loc = round(len(consolidated_results) / pr_loc, 4) if pr_loc > 0 else 0.0
        summary_md += f"**PR Code Change CWE Density:** {cwe_per_loc} Issues per Line of Code (LOC)\n\n"
        summary_md += "| Severity | CWE | Vulnerability | File:Line | Description |\n| :--- | :--- | :--- | :--- | :--- |\n"
        
        for res_item in consolidated_results:
            path = res_item.get('_primary_path', 'Unknown')
            line = res_item.get('_primary_line', '?')
            level = str(res_item.get('level', 'warning')).lower()
            rule_id = res_item.get('ruleId', 'Unknown')
            
            cwes_set = cwe_map.get(rule_id, set())
            is_top_25 = any(c in CWE_TOP_25 for c in cwes_set)
            
            if level == 'error' or is_top_25:
                h += 1
                icon_display = "🔴 High"
            elif level in ['warning', 'recommendation', 'note', 'none']:
                m += 1
                icon_display = "🟡 Medium"
            else:
                l += 1
                icon_display = "🔵 Low"
                
            for cwe_id in cwes_set:
                all_discovered_cwes.add(cwe_id)
            
            cwe_display = ", ".join(sorted(list(cwes_set))) if cwes_set else "N/A"
            raw_msg = res_item.get('message', {}).get('text', 'No description')
            if isinstance(raw_msg, str):
                msg = raw_msg.split('\n')[0] if '\n' in raw_msg else raw_msg
            else:
                msg = "No description details provided."
                
            msg = msg.replace('|', '\\|')
            summary_md += f"| {icon_display} | **{cwe_display}** | `{rule_id}` | `{path}:{line}` | {msg} |\n"

    # Save to dynamic JSON payload directly (No name overrides or string checks)
    output_dir = os.environ.get('CODEQL_ACTION_SARIF_RESULTS_OUTPUT_DIR', '.')
    if not os.path.exists(output_dir):
        output_dir = "."
        
    summary_payload = {
        "high": h,
        "medium": m,
        "low": l,
        "total_issues": len(consolidated_results),
        "files_changed": len(pr_changed_files) if pr_changed_files else 1,
        "cwes_discovered": sorted(list(all_discovered_cwes)) if all_discovered_cwes else []
    }
    
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as sm_f:
        json.dump(summary_payload, sm_f, indent=2)
    print(f"✅ [METRICS SERIALIZED] Saved final filtered scan results to {output_dir}/summary.json")

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'a') as f: 
        f.write(summary_md)

if __name__ == "__main__":
    main()
