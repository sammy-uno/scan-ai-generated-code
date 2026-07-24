import json
import glob
import os
import subprocess

def get_pr_changed_lines_live(repo, pr_num):
    """
    🎯 PR LIVE FILE QUERY: Queries the GitHub CLI safely during consolidation
    to isolate true file modifications for line-level filtering context.
    """
    changed_lines = {}
    if not repo or not pr_num:
        return changed_lines
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
        print(f"File lookup fallback notice: {e}")
    return changed_lines

def get_live_pr_status(repo, pr_num):
    """
    🎯 LIVE PR STATUS ENGINE: Queries the GitHub CLI live loop directly to resolve
    open, closed, or merged parameters natively without static lookups.
    """
    if not repo or not pr_num:
        return "🟣 Merged"
    try:
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
    except Exception:
        pass
    return "🟣 Merged"

def main():
    matrix_str = os.environ.get('MATRIX_JSON', '{}')
    scan_type = os.environ.get('SCAN_TYPE', 'automated').lower()
    
    table_rows = []
    total_scanned = 0
    vulnerable_count = 0
    total_loc_scanned = 0
    
    open_count = 0
    merged_count = 0
    closed_count = 0
    
    # Locate all unpacked .sarif files in your workspace results directory to determine run track styles
    all_sarifs = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []
    is_human_run = (scan_type == 'human') or any("human" in os.environ.get('GITHUB_WORKFLOW', '').lower() or "human--" in os.path.basename(f) for f in all_sarifs)

    # Locate all unpacked success file markers in your workspace results directory
    success_markers = []
    if os.path.exists('all-results'):
        success_markers.extend(glob.glob('all-results/*.success'))
        success_markers.extend(glob.glob('all-results/**/*.success', recursive=True))
        success_markers = sorted(list(set(success_markers)))

    print("\n====================================================")
    print("📁 CONSOLIDATION DIAGNOSTIC TRACE: SCANNING DISK ASSETS")
    print("====================================================")
    print(f"Total Success Markers Discovered on Disk: {len(success_markers)}")
    for marker in success_markers:
        print(f"📦 [FOUND ASSET] Active marker: {marker}")
    print("====================================================\n")

    for f in success_markers:
        fname = os.path.basename(f)
        parent_dir = os.path.dirname(f)

        try:
            name_root = fname.replace('.success', '').replace('.failed', '')
            parts = name_root.split('--')
            if len(parts) < 5: 
                continue
            
            raw_repo, raw_pr, raw_lang, raw_agent, raw_size = "", "", "", "", ""
            idx = 0
            for item in parts:
                if idx == 0: raw_repo = item
                elif idx == 1: raw_pr = item
                elif idx == 2: raw_lang = item
                elif idx == 3: raw_agent = item
                elif idx == 4: raw_size = item
                idx += 1

            repo_path = raw_repo.replace('_SLASH_', '/')
            pr_num = raw_pr
            lang = raw_lang
            ai_agent_tool = raw_agent.replace('_', ' ')
            live_loc = int(raw_size) if raw_size.isdigit() else 100
            
            is_row_human = "human" in fname.lower() or "human" in ai_agent_tool.lower()
            
            # Initialize metrics variables standard baselines
            h, m, l = 0, 0, 0
            cwe_display = "None"
            total_issues = 0
            committed_files_count = 1

            # 🚀 EXCLUSIVE SUMMARY JSON TRACKING LAYER
            # Targets your custom-named JSON token exclusively to load pre-calculated results.
            custom_json_path = os.path.join(parent_dir, f"{name_root}.json")
            flat_json_path = os.path.join(parent_dir, "summary.json")
            target_json_path = custom_json_path if os.path.exists(custom_json_path) else (flat_json_path if os.path.exists(flat_json_path) else "")
            
            if target_json_path and os.path.exists(target_json_path):
                with open(target_json_path, 'r', encoding='utf-8') as sm_f:
                    summary_data = json.load(sm_f)
                    h = int(summary_data.get('high', summary_data.get('H', 0)))
                    m = int(summary_data.get('medium', summary_data.get('M', 0)))
                    l = int(summary_data.get('low', summary_data.get('L', 0)))
                    total_issues = int(summary_data.get('total_issues', summary_data.get('issues', h + m + l)))
                    committed_files_count = int(summary_data.get('files_changed', summary_data.get('files', 1)))
                    
                    cwes_list = summary_data.get('cwes_discovered', summary_data.get('cwes', []))
                    if isinstance(cwes_list, list):
                        cwe_display = ', '.join(sorted(cwes_list)) if cwes_list else "None"
                    else:
                        cwe_display = str(cwes_list)
            else:
                # Force clean defaults if no file was written to prevent stale data pollution
                h, m, l = 0, 0, 0
                cwe_display = "None"
                total_issues = 0

            total_scanned += 1
            total_loc_scanned += live_loc
            if total_issues > 0: 
                vulnerable_count += 1
            
            cwe_density = round(total_issues / live_loc, 4) if live_loc > 0 else 0.0
            
            base_domain = "https://github.com"
            clean_repo_path = repo_path.strip('/')
            full_url = f"{base_domain}/{clean_repo_path}/pull/{pr_num}"
            link_md = f'[#{pr_num}]({full_url})'
            
            paren_issues_files = f"{total_issues} ({committed_files_count})"
            
            # Fetch dynamic real-time lifecycle status badges from GitHub CLI
            status_badge = get_live_pr_status(clean_repo_path, pr_num)
            
            if "Open" in status_badge: open_count += 1
            elif "Merged" in status_badge: merged_count += 1
            else: closed_count += 1
            
            row_entry = {
                "repo": clean_repo_path, "link": link_md, "tool": ai_agent_tool, "lang": lang,
                "loc": live_loc, "cwes": cwe_display, "h": h, "m": m, "l": l, 
                "issues_files": paren_issues_files, "density": cwe_density, "status": status_badge
            }
            table_rows.append(row_entry)
            
        except Exception as e: 
            print(f'Error processing success metadata {fname}: {e}')

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
            
        sorted_rows = sorted(table_rows, key=lambda x: (x["repo"], x["link"]))

        for r in sorted_rows: 
            if is_human_run:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["status"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')
            else:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["status"]} | {r["tool"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')

if __name__ == "__main__": 
    main()
