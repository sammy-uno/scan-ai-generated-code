import json
import glob
import os

def main():
    search_path = os.path.join('all-results', '**', '*.sarif')
    all_files = sorted(glob.glob(search_path, recursive=True)) if os.path.exists('all-results') else []
    
    ai_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "vuln_prs": 0, "total_loc": 0}
    human_metrics = {"total": 0, "high": 0, "medium": 0, "low": 0, "scanned_prs": 0, "vuln_prs": 0, "total_loc": 0}
    
    for f in all_files:
        fname = os.path.basename(f)
        if fname == 'results.sarif' or '--' not in fname: continue
        is_human = fname.startswith("human--") or "human-" in f.lower() or "Human_Auditor" in fname

        try:
            parts = fname.replace('.sarif', '').split('--')
            if len(parts) < 5: continue
            live_loc = int(parts[4])

            with open(f, 'r', encoding='utf-8') as s: data = json.load(s)
            runs = data.get('runs', [])
            if not isinstance(runs, list) or len(runs) == 0: continue
            
            res = []
            for run in runs:
                if isinstance(run, dict): res.extend(run.get('results', []))

            h, m, l = 0, 0, 0
            for r in res:
                lvl = r.get('level', 'warning')
                if lvl == 'error': h += 1
                elif lvl == 'warning': m += 1
                else: l += 1

            target = human_metrics if is_human else ai_metrics
            target["scanned_prs"] += 1
            target["total"] += len(res)
            target["high"] += h
            target["medium"] += m
            target["low"] += l
            target["total_loc"] += live_loc
            if len(res) > 0: target["vuln_prs"] += 1

        except Exception as e: print(f"Error evaluating artifact: {e}")

    ai_density_loc = round(ai_metrics["total"] / ai_metrics["total_loc"], 5) if ai_metrics["total_loc"] > 0 else 0.0
    human_density_loc = round(human_metrics["total"] / human_metrics["total_loc"], 5) if human_metrics["total_loc"] > 0 else 0.0

    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_file, 'w', encoding='utf-8') as out:
        out.write('# ⚖️ AI vs. Human Isolated Code Change Comparison\n\n')
        out.write('### ⚔️ Introduced Vulnerabilities Group Metrics\n')
        out.write('| Evaluation Group | Total PRs Scanned | Total Code Changes Sized | Total Introduced Issues | **CWE Density (Issues/LOC)** | 🔴 High | 🟡 Medium | Vulnerable PR Ratio |\n')
        out.write('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n')
        ai_ratio = f'{ai_metrics["vuln_prs"]}/{ai_metrics["scanned_prs"]}'
        hu_ratio = f'{human_metrics["vuln_prs"]}/{human_metrics["scanned_prs"]}'
        out.write(f'| 🤖 **AI-Generated PR** | {ai_metrics["scanned_prs"]} | {ai_metrics["total_loc"]} lines | {ai_metrics["total"]} | **{ai_density_loc}** | {ai_metrics["high"]} | {ai_metrics["medium"]} | {ai_ratio} |\n')
        out.write(f'| 👨‍💻 **Human-Written PR** | {human_metrics["scanned_prs"]} | {human_metrics["total_loc"]} lines | {human_metrics["total"]} | **{human_density_loc}** | {human_metrics["high"]} | {human_metrics["medium"]} | {hu_ratio} |\n\n')

if __name__ == "__main__": main()
