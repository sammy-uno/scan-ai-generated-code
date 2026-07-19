import json
import glob
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

def convert_to_central_time(iso_str):
    """
    Converts an ISO timestamp string cleanly to Central Time (CST/CDT).
    Automatically adapts to seasonal Daylight Saving changes using IANA definitions.
    """
    if not iso_str or not isinstance(iso_str, str) or iso_str.lower() in ["n/a", "null", "none", ""]:
        return "Not Available (No Run Recorded)"
    try:
        normalized_str = iso_str.strip().replace(" ", "T")
        if "T" not in normalized_str:
            return iso_str
            
        cleaned_iso = normalized_str.replace("Z", "+00:00")
        utc_dt = datetime.fromisoformat(cleaned_iso)
        
        central_zone = ZoneInfo("America/Chicago")
        central_dt = utc_dt.astimezone(central_zone)
        return central_dt.strftime("%Y-%m-%d %I:%M:%S %p CT")
    except Exception as ex:
        print(f"Timestamp conversion parsing log notice: {ex}")
        return iso_str

def main():
    search_path = os.path.join('all-results', '**', '*.sarif')
    all_files = sorted(glob.glob(search_path, recursive=True)) if os.path.exists('all-results') else []
    
    print("==========================================")
    print("🖥Trace: RE-DOCK METRICS COMPARISON ENGINE")
    print("==========================================")
    print(f"Total matching target files found on disk: {len(all_files)}")
    print("==========================================\n")

    ai_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "vuln_prs": 0, "cwes": set()}
    human_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "vuln_prs": 0, "cwes": set()}
    
    # Standardized MITRE CWE Top 25 Threat Matrix
    CWE_TOP_25 = [
        'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
        'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
        'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
        'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
    ]

    for f in all_files:
        fname = os.path.basename(f)
        if fname == 'results.sarif' or '--' not in fname: 
            continue

        is_human = fname.startswith("human--") or "human-" in f.lower() or "Human_Auditor" in fname or "human--" in f

        try:
            with open(f, 'r', encoding='utf-8') as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list):
                continue
                
            res = []
            seen_findings = set()
            local_cwe_map = {}
            
            for run in runs:
                if not isinstance(run, dict): continue
                tool = run.get('tool', {})
                all_rules = []
                all_rules.extend(tool.get('driver', {}).get('rules', []))
                
                extensions = tool.get('extensions', [])
                if isinstance(extensions, list):
                    for ext in extensions:
                        if isinstance(ext, dict):
                            all_rules.extend(ext.get('rules', []))
                
                for rule in all_rules:
                    if not isinstance(rule, dict): continue
                    r_id = rule.get('id')
                    if not r_id: continue
                    
                    tags = rule.get('properties', {}).get('tags', [])
                    if r_id not in local_cwe_map:
                        local_cwe_map[r_id] = set()
                    for t in tags:
                        if isinstance(t, str) and 'cwe-' in t.lower():
                            c_num = t.lower().split('cwe-')[-1]
                            if len(c_num) < 3:
                                c_num = c_num.zfill(3)
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
                    
                    # Track root location only to eliminate tracing path metric duplication leaks
                    if isinstance(locs_arr, list) and len(locs_arr) > 0:
                        loc_entry = locs_arr[0]
                        if isinstance(loc_entry, dict):
                            locs = loc_entry.get('physicalLocation', {})
                            if isinstance(locs, dict):
                                primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown')
                                primary_line = locs.get('region', {}).get('startLine', '?')
                    elif isinstance(locs_arr, dict):
                        locs = locs_arr.get('physicalLocation', {})
                        if isinstance(locs, dict):
                            primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown')
                            primary_line = locs.get('region', {}).get('startLine', '?')
                                
                    fingerprint = f'{rule_id}::{primary_path}::{primary_line}'
                    if fingerprint not in seen_findings:
                        seen_findings.add(fingerprint)
                        res.append(result)

            h, m, l = 0, 0, 0
            pr_cwes = set()
            for r in res:
                if not isinstance(r, dict): continue
                r_id = r.get('ruleId', '')
                level = r.get('level', 'warning')
                cwes_for_rule = local_cwe_map.get(r_id, set())
                is_top_25 = any(c in CWE_TOP_25 for c in cwes_for_rule)
                
                if level == 'error' or is_top_25: 
                    h += 1
                elif level == 'warning': 
                    m += 1
                else: 
                    l += 1
                
                for cwe in cwes_for_rule:
                    pr_cwes.add(cwe)

            target = human_metrics if is_human else ai_metrics
            target["scanned_prs"] += 1
            target["total"] += len(res)
            target["high"] += h
            target["medium"] += m
            target["low"] += l
            if len(res) > 0: 
                target["vuln_prs"] += 1
            for cwe in pr_cwes: 
                target["cwes"].add(cwe)

        except Exception as e:
            print(f"Error evaluating artifact properties: {e}")

    ai_raw_time = os.environ.get('AI_RUN_TIME', 'N/A')
    human_raw_time = os.environ.get('HUMAN_RUN_TIME', 'N/A')
    ai_run_id = os.environ.get('AI_RUN_ID', 'null')
    human_run_id = os.environ.get('HUMAN_RUN_ID', 'null')
    repo_name = os.environ.get('REPO_NAME', 'Unknown')
    server_url = os.environ.get('SERVER_URL', 'https://github.com')
    
    ai_freshness = convert_to_central_time(ai_raw_time)
    human_freshness = convert_to_central_time(human_raw_time)

    ai_link = f"{server_url}/{repo_name}/actions/runs/{ai_run_id}" if ai_run_id != "null" else "#"
    human_link = f"{server_url}/{repo_name}/actions/runs/{human_run_id}" if human_run_id != "null" else "#"

    # Compute density ratios
    ai_density = round(ai_metrics["total"] / ai_metrics["scanned_prs"], 2) if ai_metrics["scanned_prs"] > 0 else 0.0
    human_density = round(human_metrics["total"] / human_metrics["scanned_prs"], 2) if human_metrics["scanned_prs"] > 0 else 0.0

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# ⚖️ AI vs. Human Vulnerability Comparison\n\n')
        
        out.write('### Data Freshness (Central Time)\n')
        out.write(f'- AI Scan Last Run: `{ai_freshness}`\n')
        out.write(f'- Human Scan Last Run: `{human_freshness}`\n\n')
        
        out.write('### ⚔️ High-Level Group Comparison\n')
        out.write('| Evaluation Group | Total PRs Scanned | Vulnerable PRs | Total Issues Found | CWE Density (Issues/PR) | 🔴 High | 🟡 Medium | 🔵 Low | Distinct CWEs Found |\n')
        out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        out.write(f'| 🤖 **AI-Generated PR** | {ai_metrics["scanned_prs"]} | {ai_metrics["vuln_prs"]} | {ai_metrics["total"]} | **{ai_density}** | {ai_metrics["high"]} | {ai_metrics["medium"]} | {ai_metrics["low"]} | {len(ai_metrics["cwes"])} |\n')
        out.write(f'| 👨‍💻 **Human-Written PR** | {human_metrics["scanned_prs"]} | {human_metrics["vuln_prs"]} | {human_metrics["total"]} | **{human_density}** | {human_metrics["high"]} | {human_metrics["medium"]} | {human_metrics["low"]} | {len(human_metrics["cwes"])} |\n\n')
        
        out.write('### 🔗 Detailed Actions Summaries\n')
        out.write(f'- 🤖 **View Detailed AI Scanner Workflow Summary:** [Go to Actions Run #{ai_run_id}]({ai_link}) 🔍\n')
        out.write(f'- 👨‍💻 **View Detailed Human Auditor Workflow Summary:** [Go to Actions Run #{human_run_id}]({human_link}) 🔍\n')

if __name__ == "__main__":
    main()
