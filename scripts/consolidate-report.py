import json
import glob
import os

def main():
    matrix_str = os.environ.get('MATRIX_JSON', '{}')
    scan_type = os.environ.get('SCAN_TYPE', 'automated').lower()
    
    try:
        matrix_data = json.loads(matrix_str)
        tot = len(matrix_data.get('include', []))
    except Exception: tot = 0
        
    all_files = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []
    ok_m = len(glob.glob('all-results/**/*.success', recursive=True)) if os.path.exists('all-results') else 0
    ko_m = len(glob.glob('all-results/**/*.failed', recursive=True)) if os.path.exists('all-results') else 0
    
    if tot == 0: tot = ok_m + ko_m
        
    table_rows = []
    total_scanned = 0
    vulnerable_count = 0
    total_loc_scanned = 0
    total_issues_found = 0
    
    is_human_run = (scan_type == 'human') or any("Human_Auditor" in os.path.basename(f) for f in all_files)

    for f in all_files:
        fname = os.path.basename(f)
        if fname == 'results.sarif' or '--' not in fname: continue

        try:
            name_root = fname.replace('.sarif', '')
            parts = name_root.split('--')
            if len(parts) < 5: continue
            
            repo_path = parts[0].replace('_SLASH_', '/')
            pr_num = parts[1]
            lang = parts[2]
            agent = parts[3].replace('_', ' ')
            live_loc = int(parts[4])
            total_loc_scanned += live_loc

            with open(f) as s: data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list): continue
                
            res = []
            for run in runs:
                if isinstance(run, dict): res.extend(run.get('results', []))
            
            # severity counting logic
            h, m, l = 0, 0, 0
            for r in res:
                lvl = r.get('level', 'warning')
                if lvl == 'error': h += 1
                elif lvl == 'warning': m += 1
                else: l += 1
            
            row_severity_badge = '🔴 High' if h > 0 else ('🟡 Medium' if m > 0 else ('🔵 Low' if l > 0 else '🟢 Clean'))
            
            total_scanned += 1
            total_issues_found += len(res)
            if len(res) > 0: vulnerable_count += 1
            
            cwe_density = round(len(res) / live_loc, 4) if live_loc > 0 else 0.0
            full_url = '/'.join(['https://github.com', repo_path, 'pull', pr_num])
            link_md = f'[#{pr_num}]({full_url})'
            
            if is_human_run:
                table_rows.append(f'| {repo_path} | {link_md} | {lang} | {live_loc} | **{cwe_density}** | {row_severity_badge} | {len(res)} |')
            else:
                table_rows.append(f'| {repo_path} | {link_md} | {agent} | {lang} | {live_loc} | **{cwe_density}** | {row_severity_badge} | {len(res)} |')
        except Exception as e: print(f'Error processing {fname}: {e}')
            
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
            
        for r in sorted(table_rows): out.write(f'{r}\n')

if __name__ == "__main__": main()
