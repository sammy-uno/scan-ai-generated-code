import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Search globally for open public PRs authored by Copilot or AI agents
    # Use 'author:app/github-copilot' or 'author:@copilot' for official AI PRs
    search_query = 'author:app/github-copilot is:pr state:open is:public language:java'
    search_cmd = f'gh search prs "{search_query}" --json number,repository'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No public AI-generated Java PRs found.")
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    # To scan multiple PRs in one workflow, we checkout the most recent valid one
    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        # Double-check language classification via API
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.lower().strip().split('\n')

        if "java" in raw_langs:
            print(f"Found AI-generated Java PR: {repo_full_name} (PR #{num})")
            all_langs.add("java")
            # This checkout will be the one analyzed by CodeQL
            run_command(f"gh pr checkout {num} --repo {repo_full_name}")

    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
