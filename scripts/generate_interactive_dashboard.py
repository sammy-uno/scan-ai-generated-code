import os
import json
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
    
    # Locates active dictionary context rows to dump detailed file lines instantly
    for row in data:
        if str(row.get('repo')).strip('/') == clean_repo and str(row.get('pr_num')).strip() == clean_pr:
            if 'findings_details' in row and row['findings_details']:
                return row['findings_details']
                
    clean_repo_file = repo_owner_path.replace('/', '_SLASH_')
    json_pattern = f"all-results/{clean_repo_file}--{clean_pr}--*.json"
    matched_jsons = glob.glob(json_pattern)
    
    if matched_jsons:
        try:
            with open(matched_jsons, "r", encoding="utf-8") as f_meta:
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
    os.makedirs("docs", exist_ok=True)
    
    # Pristine single-run tracking cache buffer
    pr_lookup = {}

    # 🔍 STEP 1: Deep scan all artifact slices matching your fresh cloud run
    downloaded_slices = glob.glob("all-results/*--*.json") + glob.glob("*--*.json")
    print(f"🔍 Deep scanning {len(downloaded_slices)} fresh file artifact fragments...")
    
    gh_token = os.environ.get("GH_TOKEN", "")

    for filepath in downloaded_slices:
        if "accumulated_database" in filepath or "ai_accumulated_database" in filepath: 
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
                
                embedded_details = slice_data.get('findings_details', slice_data.get('issues_list', []))
                lookup_key = (str(repo_clean).strip('/'), str(pr_clean))
                
                # LIVE LIFECYCLE STATUS FETCH: Queries GitHub API for the true current state
                live_status = "🟣 Merged"
                if gh_token:
                    try:
                        status_cmd = ["gh", "pr", "view", pr_clean, "--repo", repo_clean, "--json", "state", "--jq", ".state"]
                        raw_state = subprocess.check_output(status_cmd, text=True, errors="ignore").strip().upper()
                        if "OPEN" in raw_state:
                            live_status = "🟢 Open"
                        elif "CLOSED" in raw_state:
                            live_status = "🔴 Closed"
                        elif "MERGED" in raw_state:
                            live_status = "🟣 Merged"
                    except Exception:
                        pass

                pr_lookup[lookup_key] = {
                    "repo": repo_clean,
                    "link": f"[#{pr_clean}](https://github.com{repo_clean}/pull/{pr_clean})",
                    "tool": tool_clean, "lang": lang_clean, "loc": loc_clean, "cwes": cwes,
                    "h": h, "m": m, "l": l, "issues_files": f"{tot} ({files_impacted})",
                    "density": round(tot / loc_clean, 4) if loc_clean > 0 else 0.0,
                    "status": live_status, "has_issues_bool": tot > 0, "pr_num": pr_clean,
                    "findings_details": embedded_details
                }
        except Exception as e:
            print(f"⚠️ Error parsing slice {filepath}: {e}")

    # 🔍 STEP 2: FALLBACK EXTRACTOR WITH ROBUST LOOSE PATH MATCHING
    sarif_logs = glob.glob("all-results/*--*.sarif") + glob.glob("*.sarif")

    for s_path in sarif_logs:
        filename = os.path.basename(s_path).replace(".sarif", "")
        parts = filename.split("--")
        if len(parts) < 2: 
            continue
        repo_clean = parts[0].replace("_SLASH_", "/")
        pr_clean = parts[1]
        lookup_key = (str(repo_clean).strip('/'), str(pr_clean))
        
        if lookup_key in pr_lookup:
            valid_pr_lines = {}
            
            if gh_token:
                try:
                    print(f"🕵️ Mapping live PR code line bounds for {repo_clean} #{pr_clean}...")
                    diff_cmd = ["gh", "pr", "diff", pr_clean, "--repo", repo_clean]
                    diff_output = subprocess.check_output(diff_cmd, text=True, errors="ignore")
                    
                    current_file = None
                    line_cursor = 0
                    for line in diff_output.splitlines():
                        if line.startswith("+++ b/"):
                            current_file = line[6:].strip()
                            valid_pr_lines[current_file] = set()
                        elif line.startswith("@@ ") and current_file:
                            match = re.search(r"\+(\d+),?(\d+)?", line)
                            if match:
                                line_cursor = int(match.group(1))
                        elif current_file and line.startswith("+") and not line.startswith("+++"):
                            if current_file in valid_pr_lines:
                                valid_pr_lines[current_file].add(line_cursor)
                            line_cursor += 1
                        elif current_file and not line.startswith("-"):
                            line_cursor += 1
                except Exception as e:
                    print(f"⚠️ Could not pull line diff bounds via GitHub API: {e}")

            try:
                with open(s_path, "r", encoding="utf-8") as s_f:
                    s_data = json.load(s_f)
                    extracted_findings = []
                    filtered_h, filtered_m, filtered_l = 0, 0, 0

                    for run in s_data.get('runs', []):
                        for res in run.get('results', []):
                            v_id = res.get('ruleId', 'Static Code Defect')
                            msg = res.get('message', {}).get('text', 'Security vulnerability discovered.')
                            
                            f_path = "Unknown"
                            line_num = 0
                            
                            for loc in res.get('locations', []):
                                p_loc = loc.get('physicalLocation', {})
                                f_path = p_loc.get('artifactLocation', {}).get('uri', 'File')
                                line_num = int(p_loc.get('region', {}).get('startLine', 0))
                            
                            # 🎯 LOOSE PATH CHECK: Safely matches files regardless of leading slashes
                            file_key = str(f_path).strip().strip('/')
                            matched_file = None
                            
                            for diff_file in valid_pr_lines.keys():
                                clean_diff_file = str(diff_file).strip().strip('/')
                                if file_key in clean_diff_file or clean_diff_file in file_key:
                                    matched_file = diff_file
                                    break
                            
                            if matched_file:
                                if line_num not in valid_pr_lines[matched_file]:
                                    continue  # Skip historical flaws outside the PR code changes!
                            else:
                                if valid_pr_lines:
                                    continue  # Skip if file didn't receive additions in this PR

                            if "high" in v_id.lower() or "cwe-79" in v_id.lower() or "cwe-89" in v_id.lower():
                                filtered_h += 1
                            elif "low" in v_id.lower():
                                filtered_l += 1
                            else:
                                filtered_m += 1

                            extracted_findings.append({
                                "vulnerability": v_id,
                                "file_line": f"{f_path}#L{line_num}",
                                "description": msg
                            })
                    
                    total_filtered_issues = filtered_h + filtered_m + filtered_l
                    pr_lookup[lookup_key]['findings_details'] = extracted_findings
                    pr_lookup[lookup_key]['h'] = filtered_h
                    pr_lookup[lookup_key]['m'] = filtered_m
                    pr_lookup[lookup_key]['l'] = filtered_l
                    
                    files_changed_count = pr_lookup[lookup_key]['issues_files'].split('(')[-1].replace(')', '')
                    pr_lookup[lookup_key]['issues_files'] = f"{total_filtered_issues} ({files_changed_count})"
                    
                    # 🎯 SYNC BOUNDS: Safe triage to turn the row white if zero items remain after filtering
                    pr_lookup[lookup_key]['has_issues_bool'] = (total_filtered_issues > 0)
                    if total_filtered_issues == 0:
                        pr_lookup[lookup_key]['cwes'] = "None"
                    
            except Exception as e:
                print(f"⚠️ Error filtering vulnerabilities for {s_path}: {e}")

    compiled_fresh_list = list(pr_lookup.values())
    data = compiled_fresh_list
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # Global Metric Summary Calculation
    total_scanned = len(data)
    vulnerable_count = sum(1 for r in data if r.get('has_issues_bool', False))
    total_loc_scanned = sum(int(r.get('loc', 0)) for r in data)
    open_count = sum(1 for r in data if "Open" in r.get('status', '') or '🟢' in r.get('status', ''))
    merged_count = sum(1 for r in data if "Merged" in r.get('status', '') or '🟣' in r.get('status', ''))
    closed_count = sum(1 for r in data if "Closed" in r.get('status', '') or '🔴' in r.get('status', ''))

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
        .details-container h4 {{ margin-top: 0; color: #cf222e; }}
        .details-table {{ width: 100%; margin: 5px 0; font-size: 13px; border: 1px solid #e1e4e8; border-collapse: collapse; }}
        .details-table th {{ background-color: #eaecef; padding: 6px 12px; border: 1px solid #e1e4e8; color: #24292f; }}
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
            <li><strong>Total PRs Parsed in This Run:</strong> {total_scanned}</li>
            <li><strong>Total LOC Scanned in This Run:</strong> {total_loc_scanned} lines</li>
            <li><strong>PRs with Issues:</strong> <span class="badge badge-vuln">{vulnerable_count} ⚠️ Vulnerable</span> | <span class="badge badge-clean">{total_scanned - vulnerable_count} Clean PRs ✅</span></li>
            <li><strong>Lifecycle Breakdown:</strong> {green_emoji} Open: {open_count} | {purple_emoji} Merged: {merged_count} | {red_emoji} Closed: {closed_count}</li>
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
                    <th>Total Security Issues (Files)</th>
                </tr>
            </thead>
            <tbody>
"""

    sorted_rows = sorted(data, key=lambda x: (x.get("repo", ""), x.get("link", "")))

    for index, r in enumerate(sorted_rows):
        clean_repo = str(r.get('repo', 'None')).strip('/')
        clean_pr = str(r.get('pr_num', '0')).strip()
        
        html_link = '<a href="https://github.com' + clean_repo + '/pull/' + clean_pr + '" target="_blank">#' + clean_pr + '</a>'
        status_display = r.get('status', '🟣 Merged')
        
        # Row coloring matches filtered issue density calculations strictly
        has_flaw = (int(r.get('h', 0)) + int(r.get('m', 0)) + int(r.get('l', 0))) > 0
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
            findings_list = r.get('findings_details', [])
            if not findings_list:
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
