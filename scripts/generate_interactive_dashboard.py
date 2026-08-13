import os
import json
import subprocess
import re
import glob

def main():
    output_path = "docs/GLOBAL_INTERACTIVE_REPORT.html"
    json_path = "all-results/ai_accumulated_database.json"
    os.makedirs("all-results", exist_ok=True)
    os.makedirs("docs", exist_ok=True)
    
    pr_lookup = {}
    gh_token = os.environ.get("GH_TOKEN", "")

    print("\n=== ⚙️ STEP 1: PARSING DOWNLOADED JSON ARTIFACT SLICES ===")
    downloaded_slices = glob.glob("all-results/*--*.json") + glob.glob("*--*.json")
    print(f"📁 Found {len(downloaded_slices)} metadata slice files in workspace.")
    
    for filepath in downloaded_slices:
        if "accumulated_database" in filepath or "ai_accumulated_database" in filepath: 
            continue
        try:
            with open(filepath, "r", encoding="utf-8") as f_slice:
                slice_data = json.load(f_slice)
                filename = os.path.basename(filepath).replace(".json", "")
                parts = filename.split("--")
                if len(parts) < 4: 
                    print(f"  ⚠️ Skipping malformed slice filename format: {filename}")
                    continue
                
                # 🎯 FIXED: Direct extraction from split string to preserve raw artifact tracking names
                repo_clean = str(parts[0]).replace("_SLASH_", "/")
                pr_clean = str(parts[1])
                lang_clean = str(parts[2]) if len(parts) > 2 else "Unknown"
                tool_clean = str(parts[3]).replace("_", " ") if len(parts) > 3 else "Static Tool"
                
                raw_size = str(parts[4]) if len(parts) > 4 else "100"
                loc_clean = int(raw_size) if raw_size.isdigit() else 100
                
                h = int(slice_data.get('high', 0))
                m = int(slice_data.get('medium', 0))
                l = int(slice_data.get('low', 0))
                tot = int(slice_data.get('total_issues', h + m + l))
                
                files_impacted = int(slice_data.get('files_changed', 1))
                embedded_details = slice_data.get('findings_details', slice_data.get('issues_list', []))
                
                print(f"  📄 File parsed: '{filename}.json'")
                print(f"     ├── Repo: {repo_clean} | PR: #{pr_clean} | Engine: {tool_clean}")
                print(f"     └── Slice Counts -> Total: {tot} (High: {h}, Med: {m}, Low: {l})")
                
                lookup_key = (str(repo_clean).strip('/'), str(pr_clean), str(tool_clean))
                
                live_status = "🟣 Merged"
                if gh_token:
                    try:
                        status_cmd = ["gh", "pr", "view", pr_clean, "--repo", repo_clean, "--json", "state", "--jq", ".state"]
                        raw_state = subprocess.check_output(status_cmd, text=True, errors="ignore").strip().upper()
                        if "OPEN" in raw_state: live_status = "🟢 Open"
                        elif "CLOSED" in raw_state: live_status = "🔴 Closed"
                    except Exception: 
                        pass

                pr_lookup[lookup_key] = {
                    "repo": repo_clean,
                    "link": f'<a href="https://github.com{repo_clean}/pull/{pr_clean}" target="_blank">#{pr_clean}</a>',
                    "tool": tool_clean, 
                    "lang": lang_clean, 
                    "loc": loc_clean, 
                    "cwes": "None",
                    "h": h, "m": m, "l": l, 
                    "issues_files": f"{tot} ({files_impacted})",
                    "density": round(tot / loc_clean, 4) if loc_clean > 0 else 0.0,
                    "status": live_status, 
                    "has_issues_bool": tot > 0, 
                    "pr_num": pr_clean,
                    "findings_details": embedded_details
                }
        except Exception as e:
            print(f"  ⚠️ Error parsing slice file {filepath}: {e}")

    # --- STEP 2: PARSE SARIF LOGS & OVERWRITE WITH REAL CWEs / SEVERITIES ---
    print("\n=== 🔍 STEP 2: CORRELATING WITH DOWNLOADED RAW SARIF ARTIFACTS ===")
    sarif_logs = glob.glob("all-results/*--*.sarif") + glob.glob("*.sarif")
    print(f"📁 Found {len(sarif_logs)} SARIF data tracking files in workspace.")

    for s_path in sarif_logs:
        filename = os.path.basename(s_path).replace(".sarif", "")
        parts = filename.split("--")
        if len(parts) < 4: 
            print(f"  ⚠️ Skipping malformed SARIF filename format: {filename}")
            continue
            
        repo_clean = str(parts).replace("_SLASH_", "/")
        pr_clean = str(parts)
        tool_clean = str(parts).replace("_", " ") if len(parts) > 3 else "Static Tool"
        
        lookup_key = (str(repo_clean).strip('/'), str(pr_clean), str(tool_clean))
        print(f"\n📂 Analyzing Log: '{filename}.sarif'")
        print(f"   ├── Target Core Mapping Key -> Repo: '{repo_clean}' | PR: #{pr_clean} | Tool: '{tool_clean}'")
        
        if lookup_key in pr_lookup:
            print("   ├── ✅ Matching row profile discovered in database.")
            sarif_rule_cwe_map = {}
            valid_pr_lines = {}
            
            if gh_token:
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
                    print(f"   ├── ✂️ Git PR diff tracking mapped: {len(valid_pr_lines)} altered code file boundaries loaded.")
                except Exception as diff_err:
                    print(f"   ├── ⚠️ Warning: Failed running gh pr diff boundary analysis: {diff_err}")

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

                            rule_obj = rules_meta.get(v_id, {})
                            sarif_level = res.get('level', rule_obj.get('defaultConfiguration', {}).get('level', 'warning')).lower()
                            security_severity = str(rule_obj.get('properties', {}).get('security-severity', '5.0'))
                            
                            try:
                                severity_score = float(security_severity)
                            except ValueError:
                                severity_score = 5.0

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

                    if extracted_findings:
                        total_filtered_issues = filtered_h + filtered_m + filtered_l
                        print(f"   └── 📊 File Sync Completed: {total_filtered_issues} issues matched line boundaries (H: {filtered_h}, M: {filtered_m}, L: {filtered_l})")
                        pr_lookup[lookup_key]['findings_details'] = extracted_findings
                        pr_lookup[lookup_key]['h'] = filtered_h
                        pr_lookup[lookup_key]['m'] = filtered_m
                        pr_lookup[lookup_key]['l'] = filtered_l
                        pr_lookup[lookup_key]['has_issues_bool'] = (total_filtered_issues > 0)
                        
                        files_changed_count = pr_lookup[lookup_key]['issues_files'].split('(')[-1].replace(')', '')
                        pr_lookup[lookup_key]['issues_files'] = f"{total_filtered_issues} ({files_changed_count})"
                    else:
                        print("   └── ⚪ File Sync Completed: Zero vulnerability occurrences matched your strict PR diff line changes.")
            except Exception as e:
                print(f"   ⚠️ Error compiling SARIF payload template index {s_path}: {e}")
        else:
            print("   ├── ❌ Profile skipped: No matching repository row initialized from JSON step.")


    # --- STEP 3: CALCULATE METRICS, EXTRACT FINAL CWEs & WRITE REPORT ---
    data = list(pr_lookup.values())
    
    print("\n======================= 🛠️ CWE RESOLUTION DEBUG LOGS =======================")
    for item in data:
        active_findings = item.get('findings_details', [])
        definitions_map = item.get('sarif_definitions_map', {})
        
        print(f"📁 [ROW START] Evaluating -> {item.get('repo')} #{item.get('pr_num')} | Total findings: {len(active_findings)}")
        
        if active_findings:
            row_cwes = set()
            for bug_idx, bug in enumerate(active_findings):
                vuln_id = str(bug.get('vulnerability', 'Unknown-Rule'))
                desc_text = str(bug.get('description', ''))
                
                print(f"  🔍 [Finding #{bug_idx + 1} ({vuln_id})]:")
                
                if vuln_id in definitions_map:
                    print(f"     ├── Found matching structural tags in SARIF definitions: {definitions_map[vuln_id]}")
                    for mapping in definitions_map[vuln_id]:
                        row_cwes.add(mapping)
                
                for match in re.findall(r'cwe-(\d+)', vuln_id.lower()):
                    row_cwes.add(f"CWE-{int(match)}")
                
                for match in re.findall(r'cwe-(\d+)', desc_text.lower()):
                    row_cwes.add(f"CWE-{int(match)}")
            
            final_cwe_string = ", ".join(sorted(row_cwes)) if row_cwes else "Vulnerability Detected"
            item['cwes'] = final_cwe_string
            print(f"  🎯 [ROW RESULT -> {item.get('repo')}]: Final 'cwes' string assigned: '{final_cwe_string}'")
        else:
            item['cwes'] = "None"
            print(f"  ✅ [ROW RESULT -> {item.get('repo')}]: No findings present. Assigned: 'None'")
    print("============================================================================\n")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    total_scanned = len(data)
    vulnerable_count = sum(1 for x in data if x.get('has_issues_bool', False))
    total_loc_scanned = sum(int(x.get('loc', 0)) for x in data)
    open_count = sum(1 for x in data if "Open" in x.get('status', ''))
    merged_count = sum(1 for x in data if "Merged" in x.get('status', ''))
    closed_count = sum(1 for x in data if "Closed" in x.get('status', ''))

    # Generate Top-Level static boilerplate HTML framework block strings
    header_html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>AI Scanner - Summary Report</title>
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
        <h3>📈 Executive Summary</h3>
        <ul>
            <li><strong>Total PRs Compiled:</strong> {total_scanned}</li>
            <li><strong>Total LOC Scanned:</strong> {total_loc_scanned} lines</li>
            <li><strong>Status:</strong> <span class="badge badge-vuln">{vulnerable_count} Vulnerable</span> | <span class="badge badge-clean">{total_scanned - vulnerable_count} Clean</span></li>
            <li><strong>Lifecycle Status Breakdown:</strong> 🟢 Open: {open_count} | 🟣 Merged: {merged_count} | 🔴 Closed: {closed_count}</li>
        </ul>
    </div>
    <h3>🔍 Detailed Scan Records Ledger</h3>
    <table><thead><tr><th>Security Alert Status</th><th>Repository Target</th><th>PR Reference Link</th><th>Status</th><th>AI Tool Engine</th><th>Language</th><th>LOC</th><th>CWE Discovered</th><th>🔴 H</th><th>🟡 M</th><th>🔵 L</th><th>Total Issues (Files)</th></tr></thead><tbody>"""

    body_html = ""
    for index, r in enumerate(data):
        row_id = f"details_{index}"
        has_flaw = r.get('has_issues_bool', False)
        cwes_found = r.get('cwes', 'None')
        
        row_class = ' class="vulnerable-row"' if has_flaw else ''
        alert_prefix = f'<button class="toggle-btn" onclick="toggleDetails(\'{row_id}\', this)">▶ View Details</button> <span class="badge badge-vuln">⚠️ VULNERABLE</span>' if has_flaw else '<span class="badge badge-clean">✅ Clean</span>'
        cwe_display = f"<code>{cwes_found}</code>" if has_flaw else (cwes_found if cwes_found == "None" else f"<code>{cwes_found}</code>")

        body_html += f"""
        <tr{row_class}>
            <td>{alert_prefix}</td>
            <td>{r.get('repo', 'None')}</td>
            <td>{r.get('link', '#')}</td>
            <td>{r.get('status', '🟣 Merged')}</td>
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
            sub_table_rows = ""
            for bug in r.get('findings_details', []):
                vuln_title = bug.get('vulnerability', 'Static Analysis Issue')
                
                display_rule_text = vuln_title
                found_digits = re.findall(r'cwe-(\d+)', vuln_title.lower())
                if found_digits:
                    cleaned_title = vuln_title
                    for d in found_digits:
                        cleaned_title = re.sub(rf'(?i)\(?cwe-0*{d}\b\)?', '', cleaned_title)
                    cleaned_title = cleaned_title.strip(" ,()[]-")
                    normalized_labels = sorted(list(set(f"CWE-{int(d)}" for d in found_digits)))
                    display_rule_text = f"{cleaned_title} ({', '.join(normalized_labels)})" if cleaned_title else ", ".join(normalized_labels)

                sub_table_rows += f"""
                <tr>
                    <td><strong>{bug.get('severity_label', '🟡 Medium')}</strong></td>
                    <td><strong>{display_rule_text}</strong></td>
                    <td><code>{bug.get('file_line', 'Unknown')}</code></td>
                    <td>{bug.get('description', 'No details provided.')}</td>
                </tr>"""

            body_html += f"""
            <tr id="{row_id}" class="details-row"><td colspan="12"><div class="details-container">
                <h4>📋 Discovered Weakness Deep-Dive Evidence (PR CWE Change Density: {r.get('density', 0.0)}):</h4>
                <table class="details-table"><thead><tr><th style="width:15%;">Security</th><th style="width:20%;">Vulnerability Rule</th><th style="width:25%;">File Location & Line</th><th style="width:40%;">Defect Context Description</th></tr></thead><tbody>
                {sub_table_rows}
                </tbody></table></div></td></tr>"""

    footer_html = "</tbody></table></body></html>"

    with open(output_path, "w", encoding="utf-8", newline="\n") as out:
        out.write(header_html + body_html + footer_html)
    print(f"✨ SUCCESS: HTML Reporting dashboard compiled at: {output_path}")

if __name__ == "__main__":
    main()
