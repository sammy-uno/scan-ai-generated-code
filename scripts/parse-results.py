import json
import os
import re
import subprocess
import sys

import json
import os
import re
import subprocess
import sys

def get_pr_changed_lines(repo, pr_num):
    """
    🎯 BULLETPROOF GIT REF PARSER: Completely drops flakey JSON view APIs.
    Queries the local workspace git diff log directly to grab accurate line mappings.
    """
    changed_lines = {}  # Maps file_path -> set of changed line numbers
    try:
        print("\n====================================================")
        print("📥 LOCAL WORKSPACE TRACE: PARSING ACTIVE GIT DIFF")
        print("====================================================")
        
        # 🚀 STRATEGY FIX: Run standard local git diff on the active pull request branch head
        # This bypasses all 'gh pr view' JSON fields API timeouts and exit codes entirely!
        cmd = "git diff HEAD~1 HEAD"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
        
        # Fallback if the merge commit depth differs on the runner workspace node
        if res.returncode != 0 or not res.stdout.strip():
            cmd = "git diff origin/main...HEAD"
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
            
        if res.returncode != 0:
            print(f"⚠️ Local Workspace Git Query Warning code: {res.returncode}")
            print(f"🔍 Stderr details: {res.stderr}")
            return changed_lines
            
        # Parse the unified diff text format directly from your local terminal buffer
        current_file = None
        current_line = 0
        hunk_re = re.compile(r'@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@')
        
        for line in res.stdout.split('\n'):
            if line.startswith('+++ b/'):
                # Extract the standardized relative destination file path string
                current_file = line[6:].strip()
                if current_file not in changed_lines:
                    changed_lines[current_file] = set()
            elif line.startswith('@@') and current_file:
                match = hunk_re.match(line)
                if match:
                    try:
                        current_line = int(match.group(1))
                    except Exception:
                        pass
            elif line.startswith('+') and not line.startswith('+++') and current_file:
                # Record the coordinate position of the newly introduced line of code change
                changed_lines[current_file].add(current_line)
                current_line += 1
            elif not line.startswith('-') and current_file:
                current_line += 1
                
        for path, line_set in changed_lines.items():
            print(f"✅ [DIFF TRACE] File '{path}' -> Successfully captured {len(line_set)} line coordinates.")
        print("====================================================\n")
                    
    except Exception as e:
        print(f"❌ [CRITICAL] Error parsing workspace diff map context: {e}")
    return changed_lines

    
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

    # Fetch the exact lines modified by the agent
    pr_diff_map = get_pr_changed_lines(repo, pr_num) if repo and pr_num else {}
    print(f"🔍 [TRACE MASTER MATRIX] Final Complete PR File Change Map Keys: {list(pr_diff_map.keys())}")
        
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

    # --- AGGREGATE RESULTS & FILTER BY PR DELTA LINES ---
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
                loc_entry = locs_arr
                if isinstance(loc_entry, dict):
                    locs = loc_entry.get('physicalLocation', {})
                    if isinstance(locs, dict):
                        primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown').strip()
                        primary_line = locs.get('region', {}).get('startLine', '?')

            # 🚀 STRICT DELTA FILTER GATEWAY
            if pr_diff_map:
                matching_file = next((p for p in pr_diff_map.keys() if primary_path.endswith(p) or p.endswith(primary_path)), None)
                if not matching_file:
                    print(f"❌ [FILTERED OUT] Alert `{rule_id}` at `{primary_path}:{primary_line}` -> File not changed in this PR.")
                    continue
                
                if primary_line == '?':
                    print(f"❌ [FILTERED OUT] Alert `{rule_id}` at `{primary_path}:{primary_line}` -> Missing specific line coordinate markers.")
                    continue
                    
                if int(primary_line) not in pr_diff_map[matching_file]:
                    print(f"❌ [FILTERED OUT] Alert `{rule_id}` at `{primary_path}:{primary_line}` -> Line pre-existed (Repository Technical Debt).")
                    continue
                
                print(f"🟢 [KEEP ALERT] Alert `{rule_id}` at `{primary_path}:{primary_line}` explicitly sits inside the introduced PR diff hunk footprint!")

            fingerprint = f"{rule_id}::{primary_path}::{primary_line}"
            if fingerprint not in seen_findings:
                seen_findings.add(fingerprint)
                res['_primary_path'] = primary_path
                res['_primary_line'] = primary_line
                consolidated_results.append(res)

    # Overwrite results.sarif with only the filtered introduced findings
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
                msg = raw_msg.split('\n') if '\n' in raw_msg else raw_msg
            else:
                msg = "No description details provided."
                
            msg = msg.replace('|', '\\|')
            
            summary_md += f"| {icon_display} | **{cwe_display}** | `{rule_id}` | `{path}:{line}` | {msg} |\n"

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'a') as f: 
        f.write(summary_md)

if __name__ == "__main__":
    main()
