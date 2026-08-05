import json
import glob
import os
import subprocess

def get_live_pr_status(repo, pr_num):
    """
    🎯 LIVE PR STATUS ENGINE: Queries the GitHub CLI live loop directly to resolve
    open, closed, or merged parameters natively without static lookups.
    """
    if not repo or not pr_num: 
        return "🟣 Merged"
    try:
        cmd = f"gh pr view {pr_num} --repo {repo} --json state"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
        if res.returncode == 0:
            raw_state = str(json.loads(res.stdout).get('state', 'CLOSED')).strip().upper()
            if raw_state == "MERGED": return "🟣 Merged"
            elif raw_state == "OPEN": return "🟢 Open"
            else: return "🔴 Closed"
    except Exception: 
        pass
    return "🟣 Merged"

def main():
    scan_type = os.environ.get('SCAN_TYPE', 'automated').lower()
    table_rows = []
    
    # 🚀 GLOBAL REGISTRATION CACHE FILE DESTINATION
    accumulated_db_path = "all-results/test_accumulated_database_v2.json"
    seen_pr_keys = set()

    # Step 1: Safely load historical database rows from previous batch tracking runs
    if os.path.exists(accumulated_db_path):
        try:
            with open(accumulated_db_path, "r", encoding="utf-8") as db_f:
                historical_rows = json.load(db_f)
                if isinstance(historical_rows, list):
                    for r in historical_rows:
                        # Normalize inputs and map keys cleanly into our active session array
                        table_rows.append(r)
                        # Build a unique verification key to prevent duplicate line pollution
                        seen_pr_keys.add(f"{r.get('repo')}#{r.get('link')}")
                    print(f"📥 [DATABASE SYNCED] Loaded {len(historical_rows)} PR records from previous batch runs.")
        except Exception as db_err:
            print(f"⚠️ Failed to ingest historical row cache database: {db_err}")

    # Step 2: Locate all active fanned matrix success markers in the workspace directory
    all_sarifs = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []
    is_human_run = (scan_type == 'human') or any("human" in os.environ.get('GITHUB_WORKFLOW', '').lower() or "human--" in os.path.basename(f) for f in all_sarifs)

    success_markers = []
    if os.path.exists('all-results'):
        success_markers.extend(glob.glob('all-results/*.success'))
        success_markers.extend(glob.glob('all-results/**/*.success', recursive=True))
        success_markers = sorted(list(set(success_markers)))

    print(f"📦 [FOUND ASSETS] Active session markers discovered on disk: {len(success_markers)}")

    # Step 3: Loop over live success markers on disk for the current batch
    for f in success_markers:
        fname = os.path.basename(f)
        parent_dir = os.path.dirname(f)

        try:
            name_root = fname.replace('.success', '').replace('.failed', '')
            parts = name_root.split('--')
            if len(parts) < 5: 
                continue
            
            # Extract historical file context segments cleanly via explicit indexing
            repo_path = parts[0].replace('_SLASH_', '/')
            pr_num = parts[1]
            lang = parts[2]
            ai_agent_tool = parts[3].replace('_', ' ')
            live_loc = int(parts[4]) if parts[4].isdigit() else 100
            
            base_domain = "https://github.com"
            clean_repo_path = repo_path.strip('/')
            full_url = f"{base_domain}/{clean_repo_path}/pull/{pr_num}"
            link_md = f'[#{pr_num}]({full_url})'

            # 🚀 CORE CHECK: If this row was already captured in a prior batch, skip parsing it again!
            if f"{clean_repo_path}#{link_md}" in seen_pr_keys:
                continue

            h, m, l, total_issues = 0, 0, 0, 0
            committed_files_count = 1

            # Ingest individual row summary files
            custom_json_path = f.replace('.success', '.json')
            nested_json_path = os.path.join(parent_dir, f"{name_root}.json")
            flat_json_path = os.path.join(parent_dir, "summary.json")
            
            target_json_path = ""
            if os.path.exists(custom_json_path): target_json_path = custom_json_path
            elif os.path.exists(nested_json_path): target_json_path = nested_json_path
            elif os.path.exists(flat_json_path): target_json_path = flat_json_path
            
            if target_json_path and os.path.exists(target_json_path):
                with open(target_json_path, 'r', encoding='utf-8') as sm_f:
                    summary_data = json.load(sm_f)
                    h = int(summary_data.get('high', summary_data.get('H', 0)))
                    m = int(summary_data.get('medium', summary_data.get('M', 0)))
                    l = int(summary_data.get('low', summary_data.get('L', 0)))
                    total_issues = int(summary_data.get('total_issues', summary_data.get('issues', h + m + l)))
                    committed_files_count = int(summary_data.get('files_changed', 1))
                    
                    cwes_list = summary_data.get('cwes_discovered', summary_data.get('cwes', []))
                    if isinstance(cwes_list, list):
                        cwe_display = ', '.join(sorted(list(set(str(c).strip().upper() for c in cwes_list if c))))
                    else:
                        cwe_display = str(cwes_list).strip().upper() if cwes_list else "None"
            else:
                cwe_display = "None"

            # Enforce density locking arithmetic rules
            if committed_files_count == 0:
                cwe_density = 0.0
            else:
                cwe_density = round(total_issues / live_loc, 4) if live_loc > 0 else 0.0
            
            paren_issues_files = f"{total_issues} ({committed_files_count})"
            status_badge = get_live_pr_status(clean_repo_path, pr_num)
            display_loc = 0 if committed_files_count == 0 else live_loc
            
            # 🚀 SCHEMA HARMONIZATION: Standardize keys to map identically for both tracks
            row_entry = {
                "repo": clean_repo_path, "link": link_md, "tool": ai_agent_tool, "lang": lang,
                "loc": display_loc, "cwes": cwe_display, "h": h, "m": m, "l": l, 
                "issues_files": paren_issues_files, "density": cwe_density, "status": status_badge,
                "has_issues_bool": total_issues > 0
            }
            table_rows.append(row_entry)
            seen_pr_keys.add(f"{clean_repo_path}#{link_md}")
            
        except Exception as e: 
            print(f'Error processing success metadata: {e}')

    # Step 4: Re-calculate accumulated macro counters across the entire unified database list
    total_scanned = len(table_rows)
    vulnerable_count = sum(1 for r in table_rows if r.get('has_issues_bool', False))
    total_loc_scanned = sum(int(r.get('loc', 0)) for r in table_rows)
    
    open_count = sum(1 for r in table_rows if "Open" in r.get('status', ''))
    merged_count = sum(1 for r in table_rows if "Merged" in r.get('status', ''))
    closed_count = sum(1 for r in table_rows if "Closed" in r.get('status', ''))

    # Save the updated master dictionary array back to disk for the next batch to read
    os.makedirs(os.path.dirname(accumulated_db_path), exist_ok=True)
    with open(accumulated_db_path, "w", encoding="utf-8") as db_w:
        json.dump(table_rows, db_w, indent=2)

    # Step 5: Write the beautifully formatted master table right to GITHUB_STEP_SUMMARY
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# 📊 Global TEST Analysis Summary\n\n### Executive Summary\n')
        out.write(f'- **Total Accumulated PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Accumulated LOC Scanned:** {total_loc_scanned} lines\n')
        out.write(f'- **PRs with Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n')
        out.write(f'- **Lifecycle Breakdown:** 🟢 Open: {open_count} | 🟣 Merged: {merged_count} | 🔴 Closed: {closed_count}\n\n')
        
        # 🚀 CONDITIONAL COLUMN HIDING ENGINE
        if is_human_run:
            out.write('\n| Repository | PR | Status | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total Security Issues (Files) | CWE Density (Issues/LOC) |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        else:
            out.write('\n| Repository | PR | Status | AI Tool | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total Security Issues (Files) | CWE Density (Issues/LOC) |\n')
            out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            
        # 🚀 ALPHABETICAL MATRIX SORTING Across all active and historical items
        sorted_rows = sorted(table_rows, key=lambda x: (x.get("repo", ""), x.get("link", "")))

        for r in sorted_rows: 
            if is_human_run:
                out.write(f'| {r.get("repo")} | {r.get("link")} | {r.get("status")} | {r.get("lang")} | {r.get("loc")} | **{r.get("cwes")}** | {r.get("h")} | {r.get("m")} | {r.get("l")} | **{r.get("issues_files")}** | **{r.get("density")}** |\n')
            else:
                out.write(f'| {r["repo"]} | {r["link"]} | {r["status"]} | {r["tool"]} | {r["lang"]} | {r["loc"]} | **{r["cwes"]}** | {r["h"]} | {r["m"]} | {r["l"]} | **{r["issues_files"]}** | **{r["density"]}** |\n')

    print(f"✅ [CONSOLIDATION COMPLETE] Successfully rendered accumulated metrics row database table to {summary_file}")

if __name__ == "__main__": 
    main()
