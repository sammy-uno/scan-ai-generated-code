import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # Get current user to exclude self
    user_res = run_command('gh api user --jq .login')
    current_user = user_res.stdout.strip()

    # BROAD SEARCH: Search for PRs with "copilot/" in branch/keywords, excluding you
    # We remove the strict language:java here and check it manually in the loop
    search_query = f'copilot/ -author:{current_user} is:pr state:open is:public'
    search_cmd = f'gh search prs "{search_query}" --json number,repository'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No public PRs found with that branch name.")
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        # Manually check for Java/Kotlin files using gh repo view
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.lower().strip().split('\n')

        if any("java" in l for l in raw_langs):
            print(f"Found Java in {repo_full_name} (PR #{num})")
            all_langs.add("java")
            # Checkout the latest match to scan
            run_command(f"gh pr checkout {num} --repo {repo_full_name}")

    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
