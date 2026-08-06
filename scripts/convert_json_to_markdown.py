import json
import os

def main():
    json_path = "all-results/accumulated_database.json"
    output_path = "GLOBAL_SUMMARY_REPORT.md"
    
    if not os.path.exists(json_path):
        print(f"❌ Error: Cannot locate '{json_path}'. Make sure you are running the script from the root folder.")
        return

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error parsing JSON database file: {e}")
        return

    if not isinstance(data, list):
        print("❌ Error: JSON structure is not a list of entries.")
        return

    # Calculate global counters
    total_scanned = len(data)
    vulnerable_count = sum(1 for r in data if r.get('has_issues_bool', False))
    total_loc_scanned = sum(int(r.get('loc', 0)) for r in data)
    
    open_count = sum(1 for r in data if "Open" in r.get('status', ''))
    merged_count = sum(1 for r in data if "Merged" in r.get('status', ''))
    closed_count = sum(1 for r in data if "Closed" in r.get('status', ''))

    print(f"📊 Processing {total_scanned} records from JSON database...")

    with open(output_path, "w", encoding="utf-8") as out:
        # Write Executive Metrics
        out.write('# 📊 Global Analysis Summary\n\n### Executive Summary\n')
        out.write(f'- **Total Accumulated PRs Parsed:** {total_scanned}\n')
        out.write(f'- **Total Accumulated LOC Scanned:** {total_loc_scanned} lines\n')
        out.write(f'- **PRs with Issues:** {vulnerable_count} ⚠️ | **Clean PRs:** {total_scanned - vulnerable_count} ✅\n')
        out.write(f'- **Lifecycle Breakdown:** 🟢 Open: {open_count} | 🟣 Merged: {merged_count} | 🔴 Closed: {closed_count}\n\n')
        
        # Write Data Table Structure Header
        out.write('### Detailed Scan Records Table\n\n')
        out.write('| Repository Target | PR Reference | AI Tool Engine | Language | LOC | CWE Discovered | 🔴 H | 🟡 M | 🔵 L | Total Security Issues (Files) |\n')
        out.write('| :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |\n')
        
        # Sort data uniformly by repository name
        sorted_rows = sorted(data, key=lambda x: (x.get("repo", ""), x.get("link", "")))
        
        for r in sorted_rows:
            # Strip markdown bracket tags from link field to maintain clean cell layout text strings
            clean_link = r.get('link', '')
            out.write(
                f"| {r.get('repo', 'None')} | {clean_link} | {r.get('tool', 'None')} | {r.get('lang', 'None')} | {r.get('loc', 0)} | "
                f"**{r.get('cwes', 'None')}** | {r.get('h', 0)} | {r.get('m', 0)} | {r.get('l', 0)} | **{r.get('issues_files', '0 (0)')}** |\n"
            )

    print(f"✨ Success! Beautiful markup report generated cleanly at: {output_path}")

if __name__ == "__main__":
    main()
