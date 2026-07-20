import json
import glob
import os
import subprocess

def get_pr_changed_lines_live(repo, pr_num):
    """
    🎯 AGGREGATOR FILTER: Queries the stable files endpoint directly during 
    consolidation to ensure no background debt slips into the final dashboard table rows.
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
                if not path: continue
                if path not in changed_lines:
                    changed_lines[path] = set()
                hunks = f.get('hunks', [])
                for hunk in hunks:
                    start_line = hunk.get('newStartLine', 0)
                    lines_count = hunk.get('newLinesCount', 0)
                    if start_line > 0 and lines_count > 0:
                        for offset in range(lines_count):
                            changed_lines[path].add(start_line + offset)
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
        
    all_files = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []
    ok_m = len(glob.glob('all-results/**/*.success', recursive=True)) if os.path.exists('all-results') else 0
    ko_m = len(glob.glob('all-results/**/*.failed', recursive=True)) if os.path.exists('all-results') else 0
    
    if tot == 0: 
        tot = ok_m + ko_m
        
    table_rows = []
    total_scanned = 0
    vulnerable_count = 0
    total_loc_scanned = 0
    total_issues_found = 0
    
    is_human_run = (scan_type == 'human') or any("Human_Auditor" in os.path.basename(f) for f in all_files)
    for f in all_files:
        fname = os.path.basename(f)
        if fname == 'results.sarif' or '--' not in fname: 
            continue

        try:
            name_root = fname.replace('.sarif', '')
            parts = name_root.split('--')
            if len(parts) < 5: 
                continue
            
            repo_path = parts[0].replace('_SLASH_', '/')
            pr_num = parts[1]
            lang = parts[2]
            agent = parts[3].replace('_', ' ')
            live_loc = int(parts[4])
            
            # Fetch the precise hunk delta map for this specific row entry
            pr_diff_map = get_pr_changed_lines_live(repo_path, pr_num)

            with open(f) as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list): 
                continue
                
            res = []
            seen_findings = set()
            
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
                                
                    # 🚀 CONSOLIDATION GATEKEEPER: Eradicate pre-existing file background debt
                    if pr_diff_map:
                        matching_file = next((p for p in pr_diff_map.keys() if primary_path.endswith(p) or p.endswith(primary_path)), None)
                        if not matching_file or primary_line == '?' or int(primary_line) not in pr_diff_map[matching_file]:
                            continue

                    fingerprint = f'{rule_id}::{primary_path}::{primary_line}'
                    if fingerprint not in seen_findings:
                        seen_findings.add(fingerprint)
                        res.append(result)
            
            # Severity badge logic for the clean delta results
            h, m, l = 0, 0, 0
            for r in res:
                lvl = r.get('level', 'warning')
                if lvl == 'error': h += 1
                elif lvl == 'warning': m += 1
                else: l += 1
            
            row_severity_badge = '🔴 High' if h > 0 else ('🟡 Medium' if m > 0 else ('🔵 Low' if l > 0 else '🟢 Clean'))
            
            total_scanned += 1
            total_loc_scanned += live_loc
            total_issues_found += len(res)
            if len(res) > 0: 
                vulnerable_count += 1
            
            cwe_density = round(len(res) / live_loc, 4) if live_loc > 0 else 0.0
            full_url = '/'.join(['https://github.com', repo_path, 'pull', pr_num])
            link_md = f'[#{pr_num}]({full_url})'
            
            if is_human_run:
                table_rows.append(f'| {repo_path} | {link_md} | {lang} | {live_loc} | **{cwe_density}** | {row_severity_badge} | {len(res)} |')
            else:
                table_rows.append(f'| {repo_path} | {link_md} | {agent} | {lang} | {live_loc} | **{cwe_density}** | {row_severity_badge} | {len(res)} |')
        except Exception as e: 
            print(f'Error processing {fname}: {e}')
            
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w') as out:
        out.write('# 📊 PR Delta Sizing Security Summary\n\n### Executive Summary\n')
        out.write(f'- **Total PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Code Slices Scanned:** {total_loc_scanned} lines\n')
        macro_density = round(total_issues_found / total_loc_scanned, 5) if total_loc_scanned > 0 else 0.0
        out.write(f'- **Group Introduced CWE Density:** {macro_density} Issues per submission Line of Code (LOC)\n')
        out.write(f'- **PRs with Introduced Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n\n')
        
        if is_human_run:
            out.write('\n| Repository | PR | Lang | PR Size (LOC) | Introduced CWE Density | Overall Severity | Total Introduced Issues |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        else:
            out.write('\n| Repository | PR | AI Tool | Lang | PR Size (LOC) | Introduced CWE Density | Overall Severity | Total Introduced Issues |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            
        for r in sorted(table_rows): 
            out.write(f'{r}\n')

if __name__ == "__main__": 
    main()
