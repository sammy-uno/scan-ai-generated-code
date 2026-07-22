import json
import glob
import os
import subprocess

def get_pr_changed_lines_live(repo, pr_num):
    """
    🎯 AGGREGATOR FILTER: Queries the stable files endpoint directly during 
    consolidation and extracts the modified file paths with credential forwarding.
    """
    changed_lines = {}
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
        print(f"Aggregator patch tracking notice: {e}")
    return changed_lines

def main():
    matrix_str = os.environ.get('MATRIX_JSON', '{}')
    scan_type = os.environ.get('SCAN_TYPE', 'automated').lower()
    
    try:
        matrix_data = json.loads(matrix_str)
        tot = len(matrix_data.get('include', []))
    except Exception: 
        tot = 0
        
    all_files = sorted(glob.glob('all-results', recursive=True)) if os.path.exists('all-results') else []
    ok_m = len(glob.glob('all-results', recursive=True)) if os.path.exists('all-results') else 0
    ko_m = len(glob.glob('all-results', recursive=True)) if os.path.exists('all-results') else 0
    
    if tot == 0: 
        tot = ok_m + ko_m
        
    table_rows = []
    total_scanned = 0
    vulnerable_count = 0
    total_loc_scanned = 0
    total_issues_found = 0
    
    is_human_run = (scan_type == 'human') or any("Human_Auditor" in os.environ.get('GITHUB_WORKFLOW', '') or "human--" in os.path.basename(f) for f in all_files)
    # Locate all unpacked .sarif files in your workspace results directory
    all_sarifs = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []

    for f in all_sarifs:
        fname = os.path.basename(f)
        if fname == 'results.sarif' or '--' not in fname: 
            continue

        try:
            name_root = fname.replace('.sarif', '').replace('.success', '').replace('.failed', '')
            parts = name_root.split('--')
            if len(parts) < 5: 
                continue
            
            # 🚀 SCHEMA ALIGNMENT UNPACKING:
            # parts[0]=repo, parts[1]=pr_num, parts[2]=language, parts[3]=agent_name, parts[4]=live_loc
            repo_path = parts[0].replace('_SLASH_', '/')
            pr_num = parts[1]
            lang = parts[2]
            ai_agent_tool = parts[3].replace('_', ' ')
            live_loc = int(parts[4]) if parts[4].isdigit() else 1
            
            # 🚀 FIXED THE DEFINITION MISMATCH: 
            # We explicitly track and assign the 'is_human' boolean right here inside the loop!
            is_human = "human" in fname.lower() or "human" in ai_agent_tool.lower()
            
            # Fetch the precise files map for this specific row entry
            pr_diff_map = get_pr_changed_lines_live(repo_path, pr_num)

            with open(f, encoding='utf-8') as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list): 
                continue
                
            res = []
            seen_findings = set()
            local_cwe_map = {}
            
            # Pre-extract rules metadata mapping to track CWE Discovered array strings
            for run in runs:
                if not isinstance(run, dict): continue
                tool = run.get('tool', {})
                all_rules = tool.get('driver', {}).get('rules', [])
                extensions = tool.get('extensions', [])
                if isinstance(extensions, list):
                    for ext in extensions:
                        if isinstance(ext, dict): 
                            all_rules.extend(ext.get('rules', []))
                
                for rule in all_rules:
                    if not isinstance(rule, dict): continue
                    r_id = rule.get('id')
                    tags = rule.get('properties', {}).get('tags', [])
                    if r_id not in local_cwe_map: 
                        local_cwe_map[r_id] = set()
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
                                
                    # CASE-INSENSITIVE FILENAME GATEKEEPER
                    if pr_diff_map:
                        alert_base = os.path.basename(primary_path).lower()
                        changed_bases = [os.path.basename(p).lower() for p in pr_diff_map.keys()]
                        if alert_base not in changed_bases:
                            continue

                    fingerprint = f'{rule_id}::{primary_path}::{primary_line}'
                    if fingerprint not in seen_findings:
                        seen_findings.add(fingerprint)
                        res.append(result)
            
            # SPLIT EMITTED ALERTS INTO EXPLICIT H, M, L DISCRETE COUNTERS
            h, m, l = 0, 0, 0
            pr_cwes = set()
            for r in res:
                r_id = r.get('ruleId', '')
                lvl = str(r.get('level', 'warning')).lower()
                cwes_for_rule = local_cwe_map.get(r_id, set())
                
                if lvl == 'error': 
                    h += 1
                elif lvl in ['warning', 'recommendation', 'note', 'none']: 
                    m += 1
                else: 
                    l += 1
                
                for cwe_id in cwes_for_rule:
                    pr_cwes.add(cwe_id)
            
            cwe_display = ', '.join(sorted(list(pr_cwes))) if pr_cwes else 'None'
            
            total_scanned += 1
            total_loc_scanned += live_loc
            total_issues_found += len(res)
            if len(res) > 0: 
                vulnerable_count += 1
            
            cwe_density = round(len(res) / live_loc, 4) if live_loc > 0 else 0.0
            full_url = '/'.join(['https://github.com', repo_path, 'pull', pr_num])
            link_md = f'[#{pr_num}]({full_url})'
            
            # Stash calculated row contents into row variables
            row_data = {
                "repo": repo_path, "link": link_md, "tool": ai_agent_tool, "lang": lang,
                "loc": live_loc, "cwes": cwe_display, "h": h, "m": m, "l": l, 
                "total_issues": len(res), "density": cwe_density
            }
            table_rows.append((is_human, row_data))
            
        except Exception as e: 
            print(f'Error processing {fname}: {e}')

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# 📊 Global Analysis Summary\n\n### Executive Summary\n')
        out.write(f'- **Total PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Exact LOC Scanned:** {total_loc_scanned} lines\n')
        out.write(f'- **PRs with Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n\n')
        
        if is_human_run:
            # Human Track Layout: 10 Columns with Severity Dots and Paren Formatting
            out.write('\n| Repository | PR | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total CWEs (Files) | CWE Density (Issues/LOC) |\n')
            out.write('\n| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        else:
            # AI Agent Track Layout: 11 Columns with Severity Dots and Paren Formatting
            out.write('\n| Repository | PR | AI Tool | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total CWEs (Files) | CWE Density (Issues/LOC) |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            
        for is_hum, r in sorted(table_rows, key=lambda x: (x[1]["repo"], x[1]["link"])): 
            if is_human_run:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')
            else:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["tool"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')

if __name__ == "__main__": 
    main()

