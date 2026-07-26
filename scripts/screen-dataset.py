import pandas as pd
import json
import os
import subprocess

def main():
    input_csv = "aidev_scan_list.csv"
    output_csv = "cwe_dense_list.csv"
    
    # Mirror your exact production script exclusions natively
    EXCLUDE_REPOS = ["BerriAI/litellm", "elastic/kibana", "tinygrad/tinygrad"]
    
    if not os.path.exists(input_csv):
        print(f"❌ Error: {input_csv} not found in workspace root.")
        return

    print("📖 Loading AIDev baseline candidate spreadsheet...")
    df = pd.read_csv(input_csv)
    
    vulnerable_prs = []
    checked_count = 0
    
    print("\n====================================================")
    print("🎯 PHASE 1 TRIGGER: SCREENING DATASET FOR ACTIVE CWES")
    print("====================================================")

    for index, row in df.iterrows():
        repo = str(row.get('repo_name', '')).strip()
        pr_num = str(row.get('number', '')).strip()
        lang = str(row.get('primary_language', '')).strip()
        agent = str(row.get('agent_name', '')).strip()
        
        if not repo or not pr_num or repo in EXCLUDE_REPOS:
            continue
            
        checked_count += 1
        print(f"🔍 [SCREENING Slot #{checked_count}] Checking: {repo} #{pr_num} [{lang}]...")
        
        # 🚀 HIGH-SPEED CLOUD PRE-CHECK QUERY:
        # Instead of launching a full heavy checkout matrix build on the runner,
        # we ask the GitHub API directly if this public repository PR hash has any 
        # pre-existing CodeQL security alerts registered in its history!
        try:
            cmd = f"gh api repos/{repo}/code-scanning/alerts?ref=refs/pull/{pr_num}/merge --limit=1"
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
            
            has_vulnerability = False
            found_cwes = []
            
            if res.returncode == 0 and res.stdout.strip():
                alerts = json.loads(res.stdout)
                if isinstance(alerts, list) and len(alerts) > 0:
                    has_vulnerability = True
                    # Extract taxonomic categories to confirm quality
                    for alert in alerts:
                        rule = alert.get('rule', {})
                        tags = rule.get('security_severity_level', rule.get('tags', []))
                        found_cwes.append(rule.get('id', 'Unknown Flaw'))
            
            if has_vulnerability:
                print(f"   🔴 [ALERT FOUND] Isolated potential defects: {found_cwes}")
                vulnerable_prs.append(row)
            else:
                print("   ✅ PR baseline evaluates as clean.")
                
        except Exception as e:
            print(f"   ⚠️ API query boundary notice: {e}")

    # Save your high-probability targeted dataset to disk
    if vulnerable_prs:
        out_df = pd.DataFrame(vulnerable_prs)
        out_df.to_csv(output_csv, index=False)
        print("====================================================")
        print(f"🎉 SCREENING COMPLETE! Saved {len(vulnerable_prs)} vulnerable PR targets to {output_csv}")
    else:
        print("====================================================")
        print("⚠️ Screening loop complete, but 0 active vulnerabilities were flagged in this pass.")

if __name__ == "__main__":
    main()
