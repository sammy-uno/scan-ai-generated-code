import json
import os
import base64
import subprocess
import re
import glob
import zipfile
from datetime import datetime, timedelta, timezone

# Global list holder referenced across script blocks to pass detail matrix payloads
data = []

def fetch_historical_artifact_data(repo_owner_path, pr_number, cwes_fallback):
    """
    🎯 LINE-FILTERED COUPLING LAYER: Prioritizes data matrices pre-bound inside global memory.
    """
    global data
    clean_repo = str(repo_owner_path).strip('/')
    clean_pr = str(pr_number).strip()
    
    # 🕵️ Locates active dictionary context rows to dump detailed file lines instantly
    for row in data:
        if str(row.get('repo')).strip('/') == clean_repo and str(row.get('pr_num')).strip() == clean_pr:
            if 'findings_details' in row and row['findings_details']:
                return row['findings_details']
                
    clean_repo_file = repo_owner_path.replace('/', '_SLASH_')
    json_pattern = f"all-results/{clean_repo_file}--{clean_pr}--*.json"
    matched_jsons = glob.glob(json_pattern)
    
    if matched_jsons:
        try:
            with open(matched_jsons[0], "r", encoding="utf-8") as f_meta:
                meta_details = json.load(f_meta)
                if 'findings_details' in meta_details and meta_details['findings_details']:
                    return meta_details['findings_details']
        except Exception: 
            pass
    return []

def main():
    global data
    output_path = "docs/GLOBAL_INTERACTIVE_REPORT.html"
    json_path = "all-results/ai_accumulated_database.json"
    os.makedirs("all-results", exist_ok=True)
    
    #sync_all_workflow_artifacts()
    
    # LOCAL ENGINE compilation fallback step
    compiled_fresh_list = []
    downloaded_slices = glob.glob("all-results/*--*.json") + glob.glob("*--*.json")
    
    for filepath in downloaded_slices:
        if "accumulated_database" in filepath: 
            continue
        try:
            with open(filepath, "r", encoding="utf-8") as f_slice:
                slice_data = json.load(f_slice)
                filename = os.path.basename(filepath).replace(".json", "")
                parts = filename.split("--")
                if len(parts) < 5: 
                    continue
                
                repo_clean = parts[0].replace("_SLASH_", "/")
                pr_clean = parts[1]
                lang_clean = parts[2]
                tool_clean = parts[3].replace("_", " ")
                raw_size  = parts[4]
                loc_clean = int(raw_size) if raw_size.isdigit() else 100
                
                h = int(slice_data.get('high', 0))
                m = int(slice_data.get('medium', 0))
                l = int(slice_data.get('low', 0))
                tot = int(slice_data.get('total_issues', h + m + l))
                cwes = slice_data.get('cwes_discovered', "None")
                if isinstance(cwes, list): 
                    cwes = ", ".join(cwes)
                files_impacted = int(slice_data.get('files_changed', 1))
                
                # 🎯 FIXED: Pulls line-filtered flaw objects right out of unzipped artifact slices
                embedded_details = slice_data.get('findings_details', slice_data.get('issues_list', []))

                # Direct live PR lifecycle checking loop
                live_status = "🟣 Merged"
                try:
                    check_cmd = f"gh pr view {pr_clean} --repo {repo_clean} --json state"
                    state_res = subprocess.run(check_cmd, capture_output=True, text=True, shell=True, timeout=10)
                    if state_res.returncode == 0:
                        state_data = json.loads(state_res.stdout)
                        raw_state = str(state_data.get('state', 'CLOSED')).upper().strip()
                        if raw_state == "MERGED": 
                            live_status = "🟣 Merged"
                        elif raw_state == "OPEN": 
                            live_status = "🟢 Open"
                        else: 
                            live_status = "🔴 Closed"
                except Exception: 
                    pass

                compiled_fresh_list.append({
                    "repo": repo_clean,
                    "link": f"[#{pr_clean}](https://github.com{repo_clean}/pull/{pr_clean})",
                    "tool": tool_clean, "lang": lang_clean, "loc": loc_clean, "cwes": cwes,
                    "h": h, "m": m, "l": l, "issues_files": f"{tot} ({files_impacted})",
                    "density": round(tot / loc_clean, 4) if loc_clean > 0 else 0.0,
                    "status": live_status, "has_issues_bool": tot > 0, "pr_num": pr_clean,
                    # 🎯 FIXED: Injects the extracted details into memory to populate your table!
                    "findings_details": embedded_details
                })
        except Exception: 
            pass
            
    data = compiled_fresh_list
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    total_scanned = len(data)
    vulnerable_count = sum(1 for r in data if r.get('has_issues_bool', False))
    total_loc_scanned = sum(int(r.get('loc', 0)) for r in data)
    open_count = sum(1 for r in data if "Open" in r.get('status', ''))
    merged_count = sum(1 for r in data if "Merged" in r.get('status', ''))
    closed_count = sum(1 for r in data if "Closed" in r.get('status', ''))

    green_emoji, purple_emoji, red_emoji, check_emoji, alert_tag = "🟢", "🟣", "🔴", "✅", "🚨"
    print(f"📊 Compiling {total_scanned} records into an interactive HTML dashboard...")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Scanner - Global Analysis Summary</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f6f8fa; margin: 0; padding: 40px; color: #24292f; }}
        h1 {{ color: #1f2328; border-bottom: 1px solid #d0d7de; padding-bottom: 10px; margin-bottom: 20px; }}
        h3 {{ margin-top: 30px; margin-bottom: 15px; color: #1f2328; }}
        .metrics-card {{ background-color: #ffffff; border: 1px solid #d0d7de; border-radius: 6px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 30px; }}
        .metrics-card ul {{ list-style-type: none; padding: 0; margin: 0; }}
        .metrics-card li {{ padding: 8px 0; border-bottom: 1px solid #f0f2f5; font-size: 15px; }}
        .table-container {{ background-color: #ffffff; border: 1px solid #d0d7de; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
        th {{ background-color: #f6f8fa; color: #57606a; padding: 12px 16px; font-weight: 600; border-bottom: 2px solid #d0d7de; }}
        td {{ padding: 12px 16px; border-bottom: 1px solid #d0d7de; vertical-align: middle; }}
        tr.main-row:hover {{ background-color: #f3f4f6 !important; }}
        .vulnerable-row {{ background-color: #ffebe9 !important; color: #82071e; }}
        .badge {{ display: inline-block; padding: 2px 8px; font-size: 12px; font-weight: 500; border-radius: 2em; text-decoration: none; }}
        .badge-vuln {{ background-color: #cf222e; color: #ffffff; }}
        .badge-clean {{ background-color: #2da44e; color: #ffffff; }}
        a {{ color: #0969da; text-decoration: none; font-weight: 600; }}
        code {{ background-color: rgba(175,184,193,0.2); padding: 0.2em 0.4em; border-radius: 6px; font-family: monospace; font-size: 85%; }}
        .details-row {{ background-color: #fafafa; display: none; }}
        .details-container {{ padding: 15px 30px; background-color: #fff8f8; border-left: 4px solid #cf222e; margin: 5px 0; }}
        .details-table {{ width: 100%; margin: 5px 0; font-size: 13px; border: 1px solid #e1e4e8; border-collapse: collapse; }}
        .details-table th {{ background-color: #eaecef; padding: 6px 12px; border: 1px solid #e1e4e8; }}
        .details-table td {{ padding: 8px 12px; background-color: #ffffff; border: 1px solid #e1e4e8; }}
        .toggle-btn {{ cursor: pointer; color: #0969da; font-weight: bold; background: none; border: none; padding: 4px 8px; font-size: 12px; }}
    </style>
    <script>
        function toggleDetails(rowId, btnElement) {{
            var element = document.getElementById(rowId);
            if (element.style.display === "table-row") {{
                element.style.display = "none";
                if(btnElement) btnElement.innerHTML = "▶ View Details";
            }} else {{
                element.style.display = "table-row";
                if(btnElement) btnElement.innerHTML = "▼ View Details";
            }}
        }}
    </script>
</head>
<body>
    <h1>📊 Global Analysis Summary</h1>
    <div class="metrics-card">
        <h3>📈 Executive Summary</h3>
        <ul>
            <li><strong>Total Accumulated PRs Parsed:</strong> {total_scanned}</li>
            <li><strong>Total Accumulated LOC Scanned:</strong> {total_loc_scanned} lines</li>
            <li><strong>Security Review Bounds:</strong> <span class="badge badge-vuln">{vulnerable_count} ⚠️ Vulnerable</span> | <span class="badge badge-clean">{total_scanned - vulnerable_count} ✅ Clean</span></li>
            <li><strong>Lifecycle Status Breakdown:</strong> {green_emoji} Open: {open_count} | {purple_emoji} Merged: {merged_count} | {red_emoji} Closed: {closed_count}</li>
        </ul>
    </div>
    <h3>🔍 Detailed Scan Records Ledger</h3>
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Security Alert Status</th>
                    <th>Repository Target</th>
                    <th>PR Reference Link</th>
                    <th>Status</th>
                    <th>AI Tool Engine</th>
                    <th>Language</th>
                    <th>LOC</th>
                    <th>CWE Discovered</th>
                    <th>🔴 H</th>
                    <th>🟡 M</th>
                    <th>🔵 L</th>
                    <th>Total Issues (Files)</th>
                </tr>
            </thead>
            <tbody>
"""

    sorted_rows = sorted(data, key=lambda x: (x.get("repo", ""), x.get("link", "")))

    for index, r in enumerate(sorted_rows):
        clean_repo = str(r.get('repo', 'None')).strip('/')
        clean_pr = str(r.get('pr_num', '0')).strip()
        
        # 🎯 LINK REPAIR COMPLETE: Explicit hardcoded trailing forward-slash added after .com natively!
        html_link = '<a href="https://github.com/' + clean_repo + '/pull/' + clean_pr + '" target="_blank">#' + clean_pr + '</a>'

        status_raw = str(r.get('status', '🟣 Merged')).strip().lower()
        if "open" in status_raw or "🟢" in status_raw: 
            status_display = f"{green_emoji} Open"
        elif "closed" in status_raw or "🔴" in status_raw: 
            status_display = f"{red_emoji} Closed"
        else: 
            status_display = f"{purple_emoji} Merged"

        has_flaw = r.get('has_issues_bool', False) or (int(r.get('h', 0)) + int(r.get('m', 0)) + int(r.get('l', 0)) > 0)
        cwes_found = r.get('cwes', 'None')
        row_id = f"details_{index}"

        if has_flaw:
            row_class = ' class="main-row vulnerable-row"'
            alert_prefix = f'<button class="toggle-btn" onclick="toggleDetails(\'{row_id}\', this)">▶ View Details</button> <span class="badge badge-vuln">{alert_tag} VULNERABLE</span>'
            cwe_display = f"<code>{cwes_found}</code>"
        else:
            row_class = ' class="main-row"'
            alert_prefix = f'<span class="badge badge-clean">{check_emoji} Clean</span>'
            cwe_display = cwes_found if cwes_found == "None" else f"<code>{cwes_found}</code>"

        density_val = r.get('density', 0.0)

        html_content += f"""
                <tr{row_class}>
                    <td>{alert_prefix}</td>
                    <td>{clean_repo}</td>
                    <td>{html_link}</td>
                    <td>{status_display}</td>
                    <td>{r.get('tool', 'None')}</td>
                    <td>{r.get('lang', 'None')}</td>
                    <td>{r.get('loc', 0)}</td>
                    <td>{cwe_display}</td>
                    <td>{r.get('h', 0)}</td>
                    <td>{r.get('m', 0)}</td>
                    <td>{r.get('l', 0)}</td>
                    <td>{r.get('issues_files', '0 (0)')}</td>
                </tr>"""

        if has_flaw:
            findings_list = fetch_historical_artifact_data(clean_repo, clean_pr, cwes_found)
            sub_table_rows = ""
            for bug in findings_list:
                vuln_title = bug.get('vulnerability', 'Static Analysis Issue')
                file_line  = bug.get('file_line', 'Unknown File Location')
                desc       = bug.get('description', 'No details provided.')
                
                bug_icon = "🟡 Medium"
                if "cwe-79" in vuln_title.lower() or "cwe-89" in vuln_title.lower() or "high" in vuln_title.lower():
                    bug_icon = "🔴 High"
                
                sub_table_rows += f"""
                            <tr>
                                <td><strong>{bug_icon}</strong></td>
                                <td><strong>{vuln_title}</strong></td>
                                <td><code>{file_line}</code></td>
                                <td>{desc}</td>
                            </tr>"""

            html_content += f"""
                <tr id="{row_id}" class="details-row">
                    <td colspan="12">
                        <div class="details-container">
                            <h4>📋 Discovered Weakness Deep-Dive Evidence (PR CWE Change Density: {density_val}):</h4>
                            <table class="details-table">
                                <thead>
                                    <tr>
                                        <th style="width: 15%;">Severity</th>
                                        <th style="width: 20%;">Vulnerability Rule</th>
                                        <th style="width: 25%;">File Location & Line Number</th>
                                        <th style="width: 40%;">Defect Context Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {sub_table_rows}
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>"""

    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8", newline="\n") as out:
        out.write(html_content)
    print(f"✨ SUCCESS: Advanced Interactive HTML data dashboard report generated at: {output_path}")

if __name__ == "__main__":
    main()
