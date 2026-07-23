import json
import glob
import os
import subprocess

def get_live_pr_status(repo, pr_num):
    """
    🎯 LIVE GENERIC LIFECYCLE QUERY: Queries the GitHub CLI API directly to pull 
    the absolute real-time state of the pull request, handling merged states correctly.
    """
    if not repo or not pr_num:
        return "🔴 Closed"
    try:
        # Request only the explicit state field to keep the API payload ultra-lightweight
        cmd = f"gh pr view {pr_num} --repo {repo} --json state"
        sub_env = os.environ.copy()
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15, env=sub_env)
        
        if res.returncode == 0:
            data = json.loads(res.stdout)
            raw_state = str(data.get('state', 'CLOSED')).strip().upper()
            
            if raw_state == "MERGED":
                return "🟣 Merged"
            elif raw_state == "OPEN":
                return "🟢 Open"
            else:
                return "🔴 Closed"
    except Exception as e:
        print(f"API status mapping fallback alert for {repo}#{pr_num}: {e}")
    return "🟣 Merged"

def main():
    matrix_str = os.environ.get('MATRIX_JSON', '{}')
    scan_type = os.environ.get('SCAN_TYPE', 'automated').lower()
    
    all_files = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []
    
    table_rows = []
    total_scanned = 0
    vulnerable_count = 0
    total_loc_scanned = 0
    
    # Live Executive Summary Counters
    open_count = 0
    merged_count = 0
    closed_count = 0

    is_human_run = (scan_type == 'human') or any("human--" in os.path.basename(f) for f in all_files)

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
            
            # 🚀 Restored your original index assignment logic explicitly:
            repo_path = parts[0].replace('_SLASH_', '/')
            pr_num = parts[1]
            lang = parts[2]
            ai_agent_tool = parts[3].replace('_', ' ')
            live_loc = int(parts[4]) if parts[4].isdigit() else 100
            
            # 🚀 GENERIC LIVE PR STATUS RESOLVER: No hardcoded dictionary lookups!
            status_badge = get_live_pr_status(repo_path, pr_num)
            
            # Dynamically increment summary totals based on the live API string response
            if "Open" in status_badge: open_count += 1
            elif "Merged" in status_badge: merged_count += 1
            else: closed_count += 1

            with open(f, 'r', encoding='utf-8') as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            if not runs or not isinstance(runs, list): 
                continue
                
            res = []
            seen_findings = set()
            local_cwe_map = {}
            
            # 🚀 RESTORED ORIGINAL STABLE METADATA RULE-TAG EXTRACTOR
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
                    if isinstance(locs_arr, list) and len(locs_arr) > 0:
                        loc_entry = locs_arr[0]
                        if isinstance(loc_entry, dict):
                            locs = loc_entry.get('physicalLocation', {})
                            if isinstance(locs, dict):
                                primary_path = locs.get('artifactLocation', {}).get('uri', 'Unknown').strip()

                    fingerprint = f'{rule_id}::{primary_path}'
                    if fingerprint not in seen_findings:
                        seen_findings.add(fingerprint)
                        res.append(result)
            
            # 🚀 RESTORED ORIGINAL CRITICAL SEVERITY COUNTERS SPLIT
            h, m, l = 0, 0, 0
            pr_cwes = set()
            for r in res:
                r_id = r.get('ruleId', '')
                lvl = str(r.get('level', 'warning')).lower()
                cwes_for_rule = local_cwe_map.get(r_id, set())
                
                if lvl == 'error': h += 1
                elif lvl in ['warning', 'recommendation', 'note', 'none']: m += 1
                else: l += 1
                
                for cwe_id in cwes_for_rule:
                    pr_cwes.add(cwe_id)
            
            cwe_display = ', '.join(sorted(list(pr_cwes))) if pr_cwes else 'None'
            
            total_scanned += 1
            total_loc_scanned += live_loc
            if len(res) > 0: 
                vulnerable_count += 1
            
            cwe_density = round(len(res) / live_loc, 4) if live_loc > 0 else 0.0
            
            base_domain = "https://github.com"
            clean_repo_path = repo_path.strip('/')
            full_url = f"{base_domain}/{clean_repo_path}/pull/{pr_num}"
            link_md = f'[#{pr_num}]({full_url})'
            
            # 🚀 DYNAMIC GENERATION BY DISK CONTENTS:
            # Queries the actual folder's stashed files array count cleanly
            committed_files_count = 1
            parent_dir_path = os.path.dirname(f)
            matching_files_pattern = os.path.join(parent_dir_path, f"{name_root}.*")
            committed_files_count = len([x for x in glob.glob(matching_files_pattern) if not x.endswith('.sarif')])
            if committed_files_count == 0:
                committed_files_count = 1
            
            paren_issues_files = f"{len(res)} ({committed_files_count})"
            
            row_entry = {
                "repo": clean_repo_path, "link": link_md, "tool": ai_agent_tool, "lang": lang,
                "loc": live_loc, "cwes": cwe_display, "h": h, "m": m, "l": l, 
                "issues_files": paren_issues_files, "density": cwe_density, "status": status_badge
            }
            table_rows.append(row_entry)
            
        except Exception as e: 
            print(f'Error processing {fname}: {e}')

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# 📊 Global Analysis Summary\n\n### Executive Summary\n')
        out.write(f'- **Total PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Exact LOC Scanned:** {total_loc_scanned} lines\n')
        out.write(f'- **PRs with Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n')
        out.write(f'- **Lifecycle Breakdown:** 🟢 Open: {open_count} | 🟣 Merged: {merged_count} | 🔴 Closed: {closed_count}\n\n')
        
        if is_human_run:
            out.write('\n| Repository | PR | Status | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total CWEs (Files) | CWE Density (Issues/LOC) |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        else:
            out.write('\n| Repository | PR | Status | AI Tool | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total CWEs (Files) | CWE Density (Issues/LOC) |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            
        # 🚀 CLEAN FLAT MATRIX ROW WRITER: Bypasses dictionary tuple sorting indices crashes natively!
        sorted_rows = sorted(table_rows, key=lambda x: (x["repo"], x["link"]))

        for r in sorted_rows: 
            if is_human_run:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["status"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')
            else:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["status"]} | {r["tool"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')

if __name__ == "__main__": 
    main()
