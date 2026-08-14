import os
import json
import subprocess
import re
import glob
import sys

def main():
    output_path = "docs/GLOBAL_INTERACTIVE_REPORT.html"
    # 🎯 SYNCHRONIZED PATH: Matches the filename managed by your workflow database branch
    json_path = "all-results/accumulated_database.json"
    os.makedirs("all-results", exist_ok=True)
    os.makedirs("docs", exist_ok=True)
    
    pr_lookup = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f_db:
                historical_records = json.load(f_db)
                for record in historical_records:
                    # Reconstruct the lowercase index mapping keys safely
                    repo = record['repo']
                    pr_num = record['pr_num']
                    tool = record['tool']
                    key = (str(repo).strip().lower(), str(pr_num).strip().lower(), str(tool).strip().lower())
                    pr_lookup[key] = record
            print(f"📁 [LEDGER LOG]: Successfully loaded {len(pr_lookup)} historical scan profiles from persistent database branch.")
        except Exception as ledger_ex:
            print(f"❌ CRITICAL FATAL ERROR: Failed parsing historical ledger records from '{json_path}': {ledger_ex}")
            sys.exit(1)
    else:
        print("📁 [LEDGER LOG]: No historical dataset ledger found. Initializing a fresh multi-batch tracking baseline.")

    gh_token = os.environ.get("GH_TOKEN", "")
    print("\n=== ⚙️ STEP 1: PARSING DOWNLOADED NEW BATCH JSON ARTIFACT SLICES ===")
    downloaded_slices = glob.glob("all-results/*.*") + glob.glob("*.*")
    
    json_slices = [
        f for f in downloaded_slices 
        if f.endswith(".json") and "--" in os.path.basename(f) and "accumulated_database" not in os.path.basename(f)
    ]
    print(f"📁 Found {len(json_slices)} fresh batch scan data results slices in workspace.")
    
    for filepath in json_slices:
        try:
            with open(filepath, "r", encoding="utf-8") as f_slice:
                slice_data = json.load(f_slice)
                filename = os.path.basename(filepath).replace(".json", "")
                
                parts = [p for p in filename.split("--") if p]
                if len(parts) < 5:
                    print(f"❌ CRITICAL FATAL ERROR: Result Filename '{filename}.json' does not match the mandatory 5-token structural schema layout.")
                    sys.exit(1)
                
                repo_raw = parts[0]
                repo_clean = repo_raw.replace("_SLASH_", "/")
                pr_clean = parts[1]
                lang_clean = parts[2]
                tool_clean = parts[3].replace("_", " ")
                
                if not pr_clean.isdigit():
                    print(f"❌ CRITICAL FATAL ERROR: Extracted Pull Request identifier '{pr_clean}' from '{filename}.json' is non-numeric.")
                    sys.exit(1)

                raw_size = slice_data.get('loc', slice_data.get('lines_of_code', parts[4]))
                if not str(raw_size).isdigit():
                    print(f"❌ CRITICAL FATAL ERROR: Lines of Code metrics missing or non-numeric inside payload file or name string: '{filename}.json'")
                    sys.exit(1)
                loc_clean = int(raw_size)
                
                h = int(slice_data['high']) if 'high' in slice_data else int(slice_data['high_issues'])
                m = int(slice_data['medium']) if 'medium' in slice_data else int(slice_data['medium_issues'])
                l = int(slice_data['low']) if 'low' in slice_data else int(slice_data['low_issues'])
                tot = int(slice_data.get('total_issues', h + m + l))
                
                files_impacted = int(slice_data['files_changed'])
                embedded_details = slice_data.get('findings_details', slice_data.get('issues_list', []))
                
                print(f"📄 [ARTIFACT LOG]: Ingesting fresh data slice -> File: '{filename}.json'")
                print(f"   ├── Target Key -> Repo: '{repo_clean}' | PR: #{pr_clean} | Tool: '{tool_clean}'")
                
                lookup_key = (str(repo_clean).strip().lower(), str(pr_clean).strip().lower(), str(tool_clean).strip().lower())
                
                if not gh_token:
                    print(f"❌ CRITICAL FATAL ERROR: GH_TOKEN environment variable is missing. Cannot fetch lifecycle status for PR #{pr_clean}.")
                    sys.exit(1)
                
                live_status = "Unknown Status"
                try:
                    status_cmd = ["gh", "pr", "view", pr_clean, "--repo", repo_clean, "--json", "state", "--jq", ".state"]
                    raw_state = subprocess.check_output(status_cmd, text=True, errors="ignore").strip().upper()
                    
                    if "OPEN" in raw_state: live_status = "🟢 Open"
                    elif "MERGED" in raw_state: live_status = "🟣 Merged"
                    elif "CLOSED" in raw_state: live_status = "🔴 Closed"
                except Exception as status_ex: 
                    print(f"   ⚠️ Notice: GitHub CLI API view lookup dropped out for '{repo_clean}' #{pr_clean}: {status_ex}")

                # Cumulative Upsert: Overwrites match profiles or inserts new entries cleanly
                pr_lookup[lookup_key] = {
                    "repo": repo_clean,
                    "link": f'<a href="https://github.com{repo_clean}/pull/{pr_clean}" target="_blank">#{pr_clean}</a>',
                    "tool": tool_clean, 
                    "lang": lang_clean, 
                    "loc": loc_clean, 
                    "cwes": "",
                    "h": h, "m": m, "l": l, 
                    "issues_files": f"{tot} ({files_impacted})",
                    "density": round(tot / loc_clean, 4) if loc_clean > 0 else 0.0,
                    "status": live_status, 
                    "has_issues_bool": tot > 0, 
                    "pr_num": pr_clean,
                    "findings_details": embedded_details
                }
        except KeyError as key_err:
            print(f"❌ CRITICAL FATAL ERROR: Missing required schema property {key_err} inside file: {filepath}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ CRITICAL FATAL ERROR: Step 1 loop processing failure on file {filepath}: {e}")
            sys.exit(1)

    # --- STEP 2: PARSE SARIF LOGS & OVERWRITE WITH REAL CWEs / SEVERITIES ---
    print("\n=== 🔍 STEP 2: CORRELATING WITH DOWNLOADED RAW SARIF ARTIFACTS ===")
    downloaded_logs = glob.glob("all-results/*.*") + glob.glob("*.*")
    
    sarif_logs = [
        f for f in downloaded_logs 
        if f.endswith(".sarif") and "--" in os.path.basename(f)
    ]
    print(f"📁 Found {len(sarif_logs)} valid SARIF data tracking files in workspace.")

    for s_path in sarif_logs:
        filename = os.path.basename(s_path).replace(".sarif", "")
        parts = [p for p in filename.split("--") if p]
        
        if len(parts) < 5:
            print(f"❌ CRITICAL FATAL ERROR: SARIF Filename '{filename}.sarif' does not match the mandatory 5-token structural schema layout.")
            sys.exit(1)
            
        repo_raw = parts[0]
        repo_clean = repo_raw.replace("_SLASH_", "/")
        pr_clean = parts[1]
        tool_clean = parts[3].replace("_", " ")
        
        if not pr_clean.isdigit():
            print(f"❌ CRITICAL FATAL ERROR: Extracted Pull Request identifier '{pr_clean}' from '{filename}.sarif' is non-numeric.")
            sys.exit(1)
        
        lookup_key = (str(repo_clean).strip().lower(), str(pr_clean).strip().lower(), str(tool_clean).strip().lower())
        print(f"\n📂 Analyzing Log Asset: '{filename}.sarif'")
        print(f"   ├── Target Extracted Lookup Key -> Repo: '{repo_clean}' | PR: #{pr_clean} | Tool: '{tool_clean}'")
        
        if lookup_key not in pr_lookup:
            print(f"❌ CRITICAL FATAL ERROR: Structural mismatch! The context {lookup_key} extracted from '{filename}.sarif' does not match any profile ledger row initialized during the JSON slice processing step.")
            sys.exit(1)
            
        print("   ├── ✅ Matrix connection established. Processing tracking payload rules...")
        sarif_rule_cwe_map = {}
        valid_pr_lines = {}
        
        try:
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
            print(f"   ├── ✂️ Git Diff: Mapped altered lines across {len(valid_pr_lines)} modified file scopes.")
        except Exception as diff_ex:
            print(f"❌ CRITICAL FATAL ERROR: Failed compiling GitHub PR diff boundaries for {repo_clean} #{pr_clean}: {diff_ex}")
            sys.exit(1)

        try:
            with open(s_path, "r", encoding="utf-8") as s_f:
                s_data = json.load(s_f)
                extracted_findings = []
                filtered_h, filtered_m, filtered_l = 0, 0, 0

                for run in s_data.get('runs', []):
                    rules_meta = {r.get('id'): r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
                    
                    print("   ├── 🛠️ [GLOBAL SARIF RULES METADATA SWEEP]:")
                    for rule_id, rule_obj in rules_meta.items():
                        found_cwes = []
                        for match in re.findall(r'cwe-(\d+)', rule_id.lower()):
                            found_cwes.append(f"CWE-{int(match)}")
                        for tag in rule_obj.get('properties', {}).get('tags', []):
                            for match in re.findall(r'cwe-(\d+)', tag.lower()):
                                found_cwes.append(f"CWE-{int(match)}")
                        if found_cwes:
                            clean_cwes = sorted(list(set(found_cwes)))
                            sarif_rule_cwe_map[rule_id] = clean_cwes
                            print(f"   │   ├── Rule '{rule_id}' structurally defines static CWE tags: {clean_cwes}")
                    
                    results_list = run.get('results', [])
                    print(f"   ├── 📊 Total vulnerability instances recorded inside this artifact file: {len(results_list)}")
                    
                    for res_idx, res in enumerate(results_list):
                        v_id = res.get('ruleId', 'Static Code Defect')
                        msg = res.get('message', {}).get('text', 'Security vulnerability discovered.')
                        f_path = "Unknown"
                        line_num = 0
                        for loc in res.get('locations', []):
                            p_loc = loc.get('physicalLocation', {})
                            f_path = p_loc.get('artifactLocation', {}).get('uri', 'File')
                            line_num = int(p_loc.get('region', {}).get('startLine', 0))
                        
                        file_key = str(f_path).strip().strip('/')
                        matched_file = None
                        for diff_file in valid_pr_lines.keys():
                            clean_diff_file = str(diff_file).strip().strip('/')
                            if file_key in clean_diff_file or clean_diff_file in file_key:
                                matched_file = diff_file
                                break
                        
                        if matched_file and line_num not in valid_pr_lines[matched_file]:
                            continue
                        elif valid_pr_lines and not matched_file:
                            continue

                        print(f"   │   🎯 [PR DIFF LINE MATCH]: Finding #{res_idx+1} passed diff boundary check -> {f_path}#L{line_num} (Rule: {v_id})")

                        sarif_level = str(res.get('level', 'warning')).lower()
                        security_severity = "5.0"
                        
                        if v_id in rules_meta:
                            rule_obj = rules_meta[v_id]
                            sarif_level = res.get('level', rule_obj.get('defaultConfiguration', {}).get('level', 'warning')).lower()
                            security_severity = str(rule_obj.get('properties', {}).get('security-severity', '5.0'))
                        else:
                            print(f"   │   ⚠️ Notice: ruleId '{v_id}' missing from driver configuration array directory. Processing native result flags.")
                        
                        try:
                            severity_score = float(security_severity)
                        except ValueError:
                            print(f"❌ CRITICAL FATAL ERROR: Non-numeric security-severity string value '{security_severity}' generated by tool configuration rules.")
                            sys.exit(1)

                        if sarif_level == "error" or severity_score >= 7.0:
                            bug_icon = "🔴 High"
                            filtered_h += 1
                        elif sarif_level == "note" or severity_score < 4.0:
                            bug_icon = "🔵 Low"
                            filtered_l += 1
                        else:
                            bug_icon = "🟡 Medium"
                            filtered_m += 1

                        extracted_findings.append({
                            "vulnerability": v_id,
                            "severity_label": bug_icon,
                            "file_line": f"{f_path}#L{line_num}",
                            "description": msg
                        })
                
                pr_lookup[lookup_key]['sarif_definitions_map'] = sarif_rule_cwe_map

                total_filtered_issues = filtered_h + filtered_m + filtered_l
                print(f"   └── 📊 File Correlation Completed: {total_filtered_issues} issues matched line boundaries (H: {filtered_h}, M: {filtered_m}, L: {filtered_l})")
                pr_lookup[lookup_key]['findings_details'] = extracted_findings
                pr_lookup[lookup_key]['h'] = filtered_h
                pr_lookup[lookup_key]['m'] = filtered_m
                pr_lookup[lookup_key]['l'] = filtered_l
                pr_lookup[lookup_key]['has_issues_bool'] = (total_filtered_issues > 0)
                
                files_changed_count = pr_lookup[lookup_key]['issues_files'].split('(')[-1].replace(')', '')
                pr_lookup[lookup_key]['issues_files'] = f"{total_filtered_issues} ({files_changed_count})"
        except Exception as e:
            print(f"❌ CRITICAL FATAL ERROR: Step 2 compilation crash on asset file {s_path}: {e}")
            sys.exit(1)

    # --- STEP 3: CALCULATE METRICS, EXTRACT FINAL CWEs & WRITE REPORT ---
    data = list(pr_lookup.values())
    
    print("\n======================= 🛠️ CWE RESOLUTION DEBUG LOGS =======================")
    for item in data:
        active_findings = item.get('findings_details', [])
        definitions_map = item.get('sarif_definitions_map', {})
        
        print(f"📁 [ROW START] Evaluating -> {item['repo']} #{item['pr_num']} | Total findings: {len(active_findings)}")
        
        if active_findings:
            row_cwes = set()
            for bug_idx, bug in enumerate(active_findings):
                vuln_id = str(bug.get('vulnerability', 'Unknown-Rule'))
                desc_text = str(bug.get('description', ''))
                
                print(f"  🔍 [Finding #{bug_idx + 1} ({vuln_id})]:")
                
                # Check 1: Parse from pre-cached global definitions map metadata tags if available
                if vuln_id in definitions_map:
                    print(f"     ├── Found matching structural tags in SARIF definitions: {definitions_map[vuln_id]}")
                    for mapping in definitions_map[vuln_id]:
                        row_cwes.add(mapping)
                
                # Check 2: Direct dynamic parsing of standard CodeQL rule identifiers to extract security tags natively
                if "xss" in vuln_id or "cross-site-scripting" in vuln_id:
                    row_cwes.add("CWE-79")
                    row_cwes.add("CWE-116")
                elif "command-injection" in vuln_id or "os-command" in vuln_id:
                    row_cwes.add("CWE-78")
                    row_cwes.add("CWE-88")
                elif "untrusted-source" in vuln_id:
                    row_cwes.add("CWE-829")
                
                # Check 3: Extract any numeric codes straight from the rule title string matching
                for match in re.findall(r'cwe[/\-_]?(\d+)', vuln_id.lower()):
                    row_cwes.add(f"CWE-{int(match)}")
                for match in re.findall(r'cwe[/\-_]?(\d+)', desc_text.lower()):
                    row_cwes.add(f"CWE-{int(match)}")
            
            final_cwe_string = ", ".join(sorted(row_cwes)) if row_cwes else "Untagged Flaw"
            item['cwes'] = final_cwe_string
            print(f"  🎯 [ROW RESULT -> {item['repo']}]: Final 'cwes' string assigned: '{final_cwe_string}'")
        else:
            item['cwes'] = "None"
            print(f"  ✅ [ROW RESULT -> {item['repo']}]: No findings present. Assigned: 'None'")
    print("============================================================================\n")

    # Save the expanded historical ledger directly back to the database file paths
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # Global summary calculations across all historical runs combined
    total_scanned = len(data)
    vulnerable_count = sum(1 for x in data if x['has_issues_bool'])
    total_loc_scanned = sum(int(x['loc']) for x in data)
    open_count = sum(1 for x in data if "Open" in x['status'])
    merged_count = sum(1 for x in data if "Merged" in x['status'])
    closed_count = sum(1 for x in data if "Closed" in x['status'])

    # Generate Top-Level static framework block strings
    header_html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>AI Multi-Language Chained Scanner - Consolidated Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto; background-color: #f6f8fa; padding: 40px; color: #24292f; }}
        h1 {{ border-bottom: 1px solid #d0d7de; padding-bottom: 10px; }}
        .card {{ background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 20px; margin-bottom: 30px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; background: #fff; border: 1px solid #d0d7de; border-radius: 6px; }}
        th {{ background: #f6f8fa; padding: 12px; font-weight: 600; border-bottom: 2px solid #d0d7de; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #d0d7de; }}
        .vulnerable-row {{ background-color: #ffebe9 !important; }}
        .badge {{ display: inline-block; padding: 2px 8px; font-size: 12px; font-weight: 500; border-radius: 2em; }}
        .badge-vuln {{ background-color: #cf222e; color: #fff; }}
        .badge-clean {{ background-color: #2da44e; color: #fff; }}
        .details-row {{ display: none; background: #fafafa; }}
        .details-container {{ padding: 15px 30px; background: #fff8f8; border-left: 4px solid #cf222e; }}
        .details-table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
        .details-table th {{ background: #eaecef; }}
        .toggle-btn {{ cursor: pointer; color: #0969da; font-weight: bold; background: none; border: none; }}
    </style>
    <script>
        function toggleDetails(rowId, btn) {{
            var el = document.getElementById(rowId);
            if (el.style.display === "table-row") {{ el.style.display = "none"; btn.innerHTML = "▶ View Details"; }}
            else {{ el.style.display = "table-row"; btn.innerHTML = "▼ View Details"; }}
        }}
    </script></head><body>
    <h1>📊 Consolidated Summary Report</h1>
    <div class="card">
        <h3>📈 Executive Summary (All Cumulative Batch Runs)</h3>
        <ul>
            <li><strong>Total PRs Parsed in This Run:</strong> {total_scanned}</li>
            <li><strong>Total LOC Scanned in This Run:</strong> {total_loc_scanned} lines</li>
            <li><strong>PRs with Issues:</strong> <span class="badge badge-vuln">{vulnerable_count} Vulnerable</span> | <span class="badge badge-clean">{total_scanned - vulnerable_count} Clean</span></li>
            <li><strong>Lifecycle Status Breakdown:</strong> 🟢 Open: {open_count} | 🟣 Merged: {merged_count} | 🔴 Closed: {closed_count}</li>
        </ul>
    </div>
    <h3>🔍 Detailed Scan Records Ledger</h3>
    <table><thead><tr><th>Security Alert Status</th><th>Repository Target</th><th>PR Reference Link</th><th>Status</th><th>AI Tool Engine</th><th>Language</th><th>LOC</th><th>CWE Discovered</th><th>🔴 H</th><th>🟡 M</th><th>🔵 L</th><th>Total Issues (Files)</th></tr></thead><tbody>"""

    body_html = ""
    for index, r in enumerate(data):
        row_id = f"details_{index}"
        has_flaw = r['has_issues_bool']
        cwes_found = r['cwes']
        definitions_map = r.get('sarif_definitions_map', {})
        
        row_class = ' class="vulnerable-row"' if has_flaw else ''
        alert_prefix = f'<button class="toggle-btn" onclick="toggleDetails(\'{row_id}\', this)">▶ View Details</button> <span class="badge badge-vuln">⚠️ VULNERABLE</span>' if has_flaw else '<span class="badge badge-clean">✅ Clean</span>'
        
        cwe_display = f"<code>{cwes_found}</code>" if has_flaw else (cwes_found if cwes_found == "None" else f"<code>{cwes_found}</code>")

        body_html += f"""
        <tr{row_class}>
            <td>{alert_prefix}</td>
            <td>{r['repo']}</td>
            <td>{r['link']}</td>
            <td>{r['status']}</td>
            <td>{r['tool']}</td>
            <td>{r['lang']}</td>
            <td>{r['loc']}</td>
            <td>{cwe_display}</td>
            <td>{r['h']}</td>
            <td>{r['m']}</td>
            <td>{r['l']}</td>
            <td>{r['issues_files']}</td>
        </tr>"""

        if has_flaw:
            sub_table_rows = ""
            for bug in r['findings_details']:
                vuln_title = bug['vulnerability']
                desc_body = bug.get('description', '')
                
                finding_cwes = set()
                if vuln_title in definitions_map:
                    for tag in definitions_map[vuln_title]:
                        finding_cwes.add(tag)
                
                # Direct dynamic parsing of standard rule identifiers
                if "xss" in vuln_title or "cross-site-scripting" in vuln_title:
                    finding_cwes.add("CWE-79")
                    finding_cwes.add("CWE-116")
                elif "command-injection" in vuln_title or "os-command" in vuln_title:
                    finding_cwes.add("CWE-78")
                    finding_cwes.add("CWE-88")
                elif "untrusted-source" in vuln_title:
                    finding_cwes.add("CWE-829")
                
                # Robust multi-pass regular expression matching
                for match in re.findall(r'cwe[/\-_]?(\d+)', vuln_title.lower()):
                    finding_cwes.add(f"CWE-{int(match)}")
                for match in re.findall(r'cwe[/\-_]?(\d+)', desc_body.lower()):
                    finding_cwes.add(f"CWE-{int(match)}")
                
                # Strict enforcement: fail immediately if a finding cannot resolve any tags
                if not finding_cwes:
                    print(f"❌ CRITICAL FATAL ERROR: Vulnerability rule instance '{vuln_title}' on active code lines lacks any valid CWE metadata definitions across pipeline logs.")
                    sys.exit(1)
                    
                cwe_label_suffix = f" ({', '.join(sorted(list(finding_cwes)))})"
                display_rule_text = f"{vuln_title}{cwe_label_suffix}"

                sub_table_rows += f"""
                <tr>
                    <td><strong>{bug['severity_label']}</strong></td>
                    <td><strong>{display_rule_text}</strong></td>
                    <td><code>{bug['file_line']}</code></td>
                    <td>{bug['description']}</td>
                </tr>"""

            body_html += f"""
            <tr id="{row_id}" class="details-row"><td colspan="12"><div class="details-container">
                <h4>📋 Discovered Weakness Deep-Dive Evidence (PR CWE Change Density: {r['density']}):</h4>
                <table class="details-table"><thead><tr><th style="width:15%;">Security</th><th style="width:20%;">Vulnerability Rule</th><th style="width:25%;">File Location & Line</th><th style="width:40%;">Defect Context Description</th></tr></thead><tbody>
                {sub_table_rows}
                </tbody></table></div></td></tr>"""

    footer_html = "</tbody></table></body></html>"

    with open(output_path, "w", encoding="utf-8", newline="\n") as out:
        out.write(header_html + body_html + footer_html)
    print(f"✨ SUCCESS: HTML Reporting dashboard compiled at: {output_path}")

if __name__ == "__main__":
    main()

