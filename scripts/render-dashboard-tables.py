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
    accumulated_db_path = "all-results/accumulated_database.json"
    
    # 🔒 CLEAN RENDER ENGINE: No local deletion hooks are present here
    seen_pr_keys = set()

    if os.path.exists(accumulated_db_path):
        try:
            with open(accumulated_db_path, "r", encoding="utf-8") as db_f:
                historical_rows = json.load(db_f)
                if isinstance(historical_rows, list):
                    for r in historical_rows:
                        table_rows.append(r)
                        current_repo = str(r.get('repo', '')).strip()
                        raw_link = str(r.get('link', ''))
                        extracted_pr = "".join(c for c in raw_link.split(']') if c.isdigit()) or "0"
                        stable_key = f"{current_repo}#{extracted_pr}"
                        seen_pr_keys.add(stable_key)
                    print(f"📥 [DASHBOARD METRICS SYNCED] Successfully loaded {len(historical_rows)} records from storage branch.")
        except Exception as db_err:
            print(f"⚠️ Failed to ingest historical rows from git database: {db_err}")

    # Check for any active markers that may exist locally
    all_sarifs = sorted(glob.glob('all-results/**/*.sarif', recursive=True)) if os.path.exists('all-results') else []
    is_human_run = (scan_type == 'human') or any("human" in os.environ.get('GITHUB_WORKFLOW', '').lower() or "human--" in os.path.basename(f) for f in all_sarifs)

    total_scanned = len(table_rows)
    vulnerable_count = sum(1 for r in table_rows if r.get('has_issues_bool', False))
    total_loc_scanned = sum(int(r.get('loc', 0)) for r in table_rows)
    
    open_count = sum(1 for r in table_rows if "Open" in r.get('status', ''))
    merged_count = sum(1 for r in table_rows if "Merged" in r.get('status', ''))
    closed_count = sum(1 for r in table_rows if "Closed" in r.get('status', ''))

    os.makedirs("report-chunks", exist_ok=True)
    with open("report-chunks/header.md", "w", encoding="utf-8") as out:
        out.write('# 📊 Global Analysis Summary\n\n### Executive Summary\n')
        out.write(f'- **Total Accumulated PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Accumulated LOC Scanned:** {total_loc_scanned} lines\n')
        out.write(f'- **PRs with Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n')
        out.write(f'- **Lifecycle Breakdown:** 🟢 Open: {open_count} | 🟣 Merged: {merged_count} | 🔴 Closed: {closed_count}\n\n')

    sorted_rows = sorted(table_rows, key=lambda x: (x.get("repo", ""), x.get("link", "")))
    chunk_size = 50
    row_chunks = [sorted_rows[i:i + chunk_size] for i in range(0, len(sorted_rows), chunk_size)]

    for index, chunk in enumerate(row_chunks):
        chunk_file = f"report-chunks/table_part_{index + 1}.md"
        with open(chunk_file, "w", encoding="utf-8") as out:
            out.write(f"\n### Detailed Scan Logs (Part {index + 1} of {len(row_chunks)})\n")
            if is_human_run:
                out.write('| Repository | PR | Status | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total Security Issues (Files) | CWE Density |\n')
                out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            else:
                out.write('| Repository | PR | Status | AI Tool | Lang | PR LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total Security Issues (Files) | CWE Density |\n')
                out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
            
            for r in chunk:
                if is_human_run:
                    out.write(f'| {r.get("repo")} | {r.get("link")} | {r.get("status")} | {r.get("lang")} | {r.get("loc")} | **{r.get("cwes")}** | {r.get("h")} | {r.get("m")} | {r.get("l")} | **{r.get("issues_files")}** | **{r.get("density")}** |\n')
                else:
                    out.write(f'| {r.get("repo")} | {r.get("link")} | {r.get("status")} | {r.get("tool")} | {r.get("lang")} | {r.get("loc")} | **{r.get("cwes")}** | {r.get("h")} | {r.get("m")} | {r.get("l")} | **{r.get("issues_files")}** | **{r.get("density")}** |\n')
                    
    print(f"🧩 Dashboard layout compiled completely into {len(row_chunks) + 1} secure chunks.")

if __name__ == "__main__":
    main()
