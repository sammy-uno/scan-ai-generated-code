import json
import os
import subprocess
import sys

def get_pr_changed_lines(repo, pr_num):
    """
    🎯 RE-ENGINEERED STRIP PARSER: Safely reads the unified patch chunks 
    returned by gh pr view to extract true code addition line matrices.
    """
    changed_lines = {}  # Maps file_path -> set of changed line numbers
    try:
        cmd = f"gh pr view {pr_num} --repo {repo} --json fileChanges"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
        if res.returncode != 0:
            print(f"⚠️ GitHub CLI query execution warning code: {res.returncode}")
            return changed_lines
            
        data = json.loads(res.stdout)
        file_changes = data.get('fileChanges', [])
        
        for change in file_changes:
            path = change.get('path', '')
            if not path: 
                continue
                
            if path not in changed_lines:
                changed_lines[path] = set()
            
            patch = change.get('patch', '')
            if not patch:
                continue
                
            current_line = 0
            for line in patch.split('\n'):
                # Safely parse unified diff meta block markers (e.g., @@ -1,4 +42,10 @@)
                if line.startswith('@@'):
                    try:
                        # Extract everything following the '+' character block cleanly as a string
                        meta_part = line.split('+')[-1].split(' @@')[0].strip()
                        if ',' in meta_part:
                            current_line = int(meta_part.split(',')[0])
                        else:
                            current_line = int(meta_part)
                    except Exception as ex:
                        print(f"Hunk metadata block parsing notice: {ex}")
                        pass
                elif line.startswith('+') and not line.startswith('+++'):
                    # Match found for code lines actually modified/added
                    changed_lines[path].add(current_line)
                    current_line += 1
                elif not line.startswith('-'):
                    # Move tracking marker forward across unmodified background context lines
                    current_line += 1
                    
    except Exception as e:
        print(f"Error parsing PR diff hunks footprint matrix: {e}")
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

    # Extract target parameters passed from workflow environment definitions
    repo = os.environ.get('PR_REPO', '')
    pr_num = os.environ.get('PR_NUM', '')
    pr_loc = int(os.environ.get('PR_LOC', '1'))

    # Fetch the exact lines modified by the agent
    pr_diff_map = get_pr_changed_lines(repo, pr_num) if repo and pr_num else {}
    print(f"🔍 [TRACE] Isolated PR File Keys: {list(pr_diff_map.keys())}")
        
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

    for run in runs:
        if not isinstance(run, dict): continue
        results = run.get('results', [])
        if not isinstance(results, list): continue
        
        for res in results:
            if not isinstance(res, dict): continue
            rule_id = res.get('ruleId', 'Unknown')
            locs_arr = res.get('locations', [])
            
            primary_path = "Unknown"
            primary_line = "?"
            
            if isinstance(locs_arr, list) and len(locs_arr) > 0:
                loc_entry = locs_arr[0] # Root finding extraction entry
                if isinstance(loc_entry, dict):
                    locs = loc_entry.get('physicalLocation', {})
                    if isinstance(locs, dict):
                        primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown')
                        primary_line = locs.get('region', {}).get('startLine', '?')

            # 🚀 STRICT DELTA FILTER GATEWAY
            if pr_diff_map:
                # Suffix-match CodeQL paths to handle varying relative file prefixes cleanly
                matching_file = next((p for p in pr_diff_map.keys() if primary_path.endswith(p)), None)
                if not matching_file or primary_line == '?' or int(primary_line) not in pr_diff_map[matching_file]:
                    continue  # Safely bypasses background pre-existing repo debt files

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
        # Clear findings out entirely if no issues were introduced in the code submission lines
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
            msg = raw_msg.split('\n') if '\n' in raw_msg else raw_msg
            msg = msg.replace('|', '\\|')
            
            summary_md += f"| {icon_display} | **{cwe_display}** | `{rule_id}` | `{path}:{line}` | {msg} |\n"

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'a') as f: 
        f.write(summary_md)

if __name__ == "__main__":
    main()
