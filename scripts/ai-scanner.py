import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Broad Global Search for AI agents and branch patterns
    # We remove the strict language:java here to find more candidates
    agents = [
        "author:app/github-copilot", 
        "author:app/sweep", 
        "author:app/coderabbitai", 
        "author:app/pixee",
        "head:copilot/",
        "head:sweep/"
    ]
    
    agent_query = " OR ".join(agents)
    # Search for PRs by AI agents that are public and open
    search_query = f'({agent_query}) is:pr state:open is:public'
    search_cmd = f'gh search prs "{search_query}" --json number,repository --limit 50'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No public AI-agent PRs found at all.")
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    # 2. Filter for Java manually by checking repo composition
    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        # Verify if the repository contains Java
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.lower().strip().split('\n')

        if any("java" in l for l in raw_langs):
            print(f"Found Java-eligible AI PR: {repo_full_name} (PR #{num})")
            all_langs.add("java")
            # Checkout this specific PR for scanning
            run_command(f"gh pr checkout {num} --repo {repo_full_name}")
            break # Stop at the first valid Java PR to scan

    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
