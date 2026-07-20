import json
import glob
import os

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
    cwe_tracker = {}
    
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
            live_loc = int(parts[4]) # 🚀 PARSES THE EXACT RUNTIME PR LOC
            total_loc_scanned += live_loc

            with open(f) as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list): continue
                
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
            
            local_cwe_map = {}
            try:
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
            except Exception as ex: 
                print(f'Metadata extract warning: {ex}')

            total_scanned += 1
            total_issues_found += len(res)
            if len(res) > 0: vulnerable_count += 1
            
            h, m, l = 0, 0, 0
            CWE_TOP_25 = [
                'CWE-79', 'CWE-89', 'CWE-352', 'CWE-862', 'CWE-787', 'CWE-22', 'CWE-416',
                'CWE-125', 'CWE-78', 'CWE-94', 'CWE-120', 'CWE-434', 'CWE-476', 'CWE-121',
                'CWE-502', 'CWE-122', 'CWE-863', 'CWE-20', 'CWE-284', 'CWE-200', 'CWE-306',
                'CWE-918', 'CWE-77', 'CWE-639', 'CWE-770'
            ]
            
            pr_cwes = set()
            for r in res:
                r_id = r.get('ruleId', '')
                level = r.get('level', 'warning')
                cwes_for_rule = local_cwe_map.get(r_id, set())
                is_top_25 = any(c in CWE_TOP_25 for c in cwes_for_rule)
                
                if level == 'error' or is_top_25: h += 1
                elif level == 'warning': m += 1
                else: l += 1
                    
                for cwe_id in cwes_for_rule:
                    cwe_tracker[cwe_id] = cwe_tracker.get(cwe_id, 0) + 1
                    pr_cwes.add(cwe_id)
            
            if h > 0: row_severity_badge = '🔴 High'
            elif m > 0: row_severity_badge = '🟡 Medium'
            elif l > 0: row_severity_badge = '🔵 Low'
            else: row_severity_badge = '🟢 Clean'
            
            cwe_display = ', '.join(sorted(list(pr_cwes))) if pr_cwes else 'None'
            
            # 🚀 TRUE DIRECT RATIO: CWE divided directly by the exact PR LOC
            cwe_density = round(len(res) / live_loc, 4) if live_loc > 0 else 0.0
            
            full_url = '/'.join(['https://github.com', repo_path, 'pull', pr_num])
            link_md = f'[#{pr_num}]({full_url})'
            
            if is_human_run:
                table_rows.append(f'| {repo_path} | {link_md} | {lang} | {live_loc} | **{cwe_density}** | {row_severity_badge} | **{cwe_display}** | {len(res)} |')
            else:
                table_rows.append(f'| {repo_path} | {link_md} | {agent} | {lang} | {live_loc} | **{cwe_density}** | {row_severity_badge} | **{cwe_display}** | {len(res)} |')
        except Exception as e:
            print(f'Error processing {fname}: {e}')
            
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w') as out:
        out.write('# 📊 Global Analysis Summary\n\n### Executive Summary\n')
        out.write(f'- **Total PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Exact LOC Scanned:** {total_loc_scanned} lines\n')
        # Macro group density calculations (Direct issues / Total LOC)
        macro_density = round(total_issues_found / total_loc_scanned, 5) if total_loc_scanned > 0 else 0.0
        out.write(f'- **Macro Group CWE Footprint Density:** {macro_density} Issues per Line of Code (LOC)\n')
        out.write(f'- **PRs with Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n\n')
        
        if is_human_run:
            out.write('\n| Repository | PR | Lang | Exact Size (LOC) | CWE Density (Issues/LOC) | Overall Severity | CWE Discovered | Total Issues |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        else:
            out.write('\n| Repository | PR | AI Tool | Lang | Exact Size (LOC) | CWE Density (Issues/LOC) | Overall Severity | CWE Discovered | Total Issues |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            
        for r in sorted(table_rows): 
            out.write(f'{r}\n')

if __name__ == "__main__":
    main()
