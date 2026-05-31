import json
import glob
import os

def main():
    all_files = sorted(glob.glob('all-results/*.sarif')) if os.path.exists('all-results') else []
    
    # Tracking repositories side by side
    ai_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "vuln_prs": 0, "cwes": set()}
    human_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "vuln_prs": 0, "cwes": set()}
    
    comparison_rows = []
    
    CWE_TOP_25 = [
        'CWE-787', 'CWE-079', 'CWE-089', 'CWE-020', 'CWE-125', 'CWE-078', 'CWE-416',
        'CWE-022', 'CWE-352', 'CWE-434', 'CWE-476', 'CWE-502', 'CWE-190', 'CWE-287',
        'CWE-798', 'CWE-862', 'CWE-732', 'CWE-269', 'CWE-306', 'CWE-362', 'CWE-522',
        'CWE-611', 'CWE-918', 'CWE-077', 'CWE-400', 'CWE-088', 'CWE-094'
    ]

    for f in all_files:
        fname = os.path.basename(f)
        if fname == 'results.sarif' or '--' not in fname: 
            continue

        # Proactive type detection
        is_human = "Human_Auditor" in fname or fname.startswith("human--")
        
        try:
            name_root = fname.replace('.sarif', '')
            parts = name_root.split('--')
            
            # --- FIX: ADAPTIVE DESERIALIZATION PREVENTS STRING INDEXERRORS ---
            if fname.startswith("human--"):
                # Handle the 3-hyphen human format: human--repo_path--pr_num--lang
                if len(parts) < 4: continue
                repo_path = parts[1].replace('_SLASH_', '/')
                pr_num = parts[2]
                lang = parts[3]
                agent = "Human Auditor"
            else:
                # Handle the standard 4-part format: repo_path--pr_num--lang--agent_name
                if len(parts) < 4: continue
                repo_path = parts[0].replace('_SLASH_', '/')
                pr_num = parts[1]
                lang = parts[2]
                agent = parts[3].replace('_', ' ')

            with open(f) as s: 
                data = json.load(s)
            runs = data.get('runs', [])
            res = []
            
            seen_findings = set()
            local_cwe_map = {}
            
            # Map rules to CWE tags safely
            for run in runs:
                if not isinstance(run, dict): continue
                tool = run.get('tool', {})
                all_rules = []
                all_rules.extend(tool.get('driver', {}).get('rules', []))
                for ext in tool.get('extensions', []):
                    all_rules.extend(ext.get('rules', []))
                
                for rule in all_rules:
                    r_id = rule.get('id')
                    tags = rule.get('properties', {}).get('tags', [])
                    if r_id not in local_cwe_map:
                        local_cwe_map[r_id] = set()
                    for t in tags:
                        if 'cwe-' in t.lower():
                            c_num = t.lower().split('cwe-')[-1]
                            local_cwe_map[r_id].add(f'CWE-{c_num.zfill(3)}'.upper())

            # Extract and deduplicate unique findings across all sub-locations
            for run in runs:
                if isinstance(run, dict):
                    for result in run.get('results', []):
                        rule_id = result.get('ruleId', 'Unknown')
                        locs_arr = result.get('locations', [])
                        
                        is_new_finding = False
                        if isinstance(locs_arr, list) and len(locs_arr) > 0:
                            for loc_entry in locs_arr:
                                if not isinstance(loc_entry, dict): continue
                                locs = loc_entry.get('physicalLocation', {})
                                path = locs.get('artifactLocation', {}).get('uri', 'Unknown')
                                line = locs.get('region', {}).get('startLine', '?')
                                
                                fingerprint = f'{rule_id}::{path}::{line}'
                                if fingerprint not in seen_findings:
                                    seen_findings.add(fingerprint)
                                    is_new_finding = True
                        elif isinstance(locs_arr, dict):
                            locs = locs_arr.get('physicalLocation', {})
                            path = locs.get('artifactLocation', {}).get('uri', 'Unknown')
                            line = locs.get('region', {}).get('startLine', '?')
                            
                            fingerprint = f'{rule_id}::{path}::{line}'
                            if fingerprint not in seen_findings:
                                seen_findings.add(fingerprint)
                                is_new_finding = True
                                
                        if is_new_finding:
                            res.append(result)

            h, m, l = 0, 0, 0
            pr_cwes = set()
            for r in res:
                r_id = r.get('ruleId', '')
                level = r.get('level', 'warning')
                cwes_for_rule = local_cwe_map.get(r_id, set())
                is_top_25 = any(c in CWE_TOP_25 for c in cwes_for_rule)
                
                if level == 'error' or is_top_25: h += 1
                elif level == 'warning': m += 1
                else: l += 1
                
                for cwe in cwes_for_rule:
                    pr_cwes.add(cwe)

            if h > 0: severity_badge = '🔴 High'
            elif m > 0: severity_badge = '🟡 Medium'
            elif l > 0: severity_badge = '🔵 Low'
            else: severity_badge = '🟢 Clean'

            cwe_display = ', '.join(sorted(list(pr_cwes))) if pr_cwes else 'None'
            
            # Increment the target tracker dictionaries accurately
            target = human_metrics if is_human else ai_metrics
            target["total"] += len(res)
            target["high"] += h
            target["medium"] += m
            target["low"] += l
            if len(res) > 0: 
                target["vuln_prs"] += 1
            for cwe in pr_cwes: 
                target["cwes"].add(cwe)

            scan_source = "Human Scan" if is_human else f"AI Run ({agent})"
            comparison_rows.append(f'| {repo_path} | [#{pr_num}](https://github.com{repo_path}/pull/{pr_num}) | {scan_source} | {lang} | {severity_badge} | **{cwe_display}** | {h} | {m} | {l} | {len(res)} |')

        except Exception as e:
            print(f'Error processing comparison payload for {fname}: {e}')

    # Output report summaries natively to the actions dashboard window
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w') as out:
        out.write('# 📊 Comparison Dashboard: AI Scans vs. Human Audits\n\n')
        
        out.write('### ⚔️ High-Level Group Comparison\n')
        out.write('| Evaluation Group | Total Issues Found | 🔴 High | 🟡 Medium | 🔵 Low | Vulnerable PRs | Distinct CWEs Found |\n')
        out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        out.write(f'| 🤖 **AI Generated Code** | {ai_metrics["total"]} | {ai_metrics["high"]} | {ai_metrics["medium"]} | {ai_metrics["low"]} | {ai_metrics["vuln_prs"]} | {len(ai_metrics["cwes"])} |\n')
        out.write(f'| 👨‍💻 **Human Manual Audits** | {human_metrics["total"]} | {human_metrics["high"]} | {human_metrics["medium"]} | {human_metrics["low"]} | {human_metrics["vuln_prs"]} | {len(human_metrics["cwes"])} |\n\n')
        
        out.write('### 📝 Detailed Side-by-Side Run Log\n')
        out.write('| Repository | Pull Request | Scan Source Profile | Language | Overall Severity | CWEs Discovered | 🔴 H | 🟡 M | 🔵 L | Total Bugs |\n')
        out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        for row in sorted(comparison_rows):
            out.write(f'{row}\n')

if __name__ == "__main__":
    main()
