import subprocess
import json
import os

def run_command(command):
    # shell=True is essential for correctly parsing quotes in Windows/Linux
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # SEARCH STRATEGY:
    # 1. Search by branch prefix (common for AI agents like Copilot/Sweep)
    # 2. Search for "copilot" keyword in public PRs
    # 3. Filter for Java repos
    search_queries = [
        'head:copilot/ language:java is:open is:public',
        'head:sweep/ language:java is:open is:public',
        'copilot language:java is:open is:public'
    ]
    
    found_any = False

    for query in search_queries:
        print(f"Trying global search query: {query}")
        # Use gh search prs which is optimized for global results
        search_cmd = f'gh search prs "{query}" --limit 10 --json number,repository'
        res = run_command(search_cmd)
        
        if res.stdout and res.stdout.strip() != "[]":
            prs = json.loads(res.stdout)
            for pr in prs:
                num = str(pr.get("number"))
                repo = pr.get("repository", {}).get("nameWithOwner")
                
                print(f"MATCH FOUND: {repo} (PR #{num}). Checking out...")
                # checkout the PR to the current runner workspace
                run_command(f"gh pr checkout {num} --repo {repo}")
                set_output("java")
                found_any = True
                return

    if not found_any:
        print("No matches found. Ensure your GLOBAL_SCAN_PAT has 'public_repo' scope.")
        set_output("")

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
