import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Search ALL public PRs starting with "copilot/"
    # We remove --repo to search globally
    search_cmd = 'gh search prs --head "copilot/" --state open --json number,repository'
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No matching PRs found.")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    # LOOP through all discovered PRs
    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        print(f"Checking out PR #{num} from {repo_full_name}...")
        
        # Checkout using explicit repo to avoid local mismatch
        run_command(f"gh pr checkout {num} --repo {repo_full_name}")
        
        # 2. Detect Languages in the checked-out PR
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        detected_langs = lang_res.stdout.lower().strip().split('\n')

        # Strictly map for Java to avoid Exit Code 32 errors
        mapping = {"java": "java-kotlin"}
        for l in detected_langs:
            if l in mapping:
                all_langs.add(mapping[l])

    # 3. Output combined languages for the next Action step
    lang_string = ",".join(all_langs)
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={lang_string}\n")
    
    print(f"Ready to scan languages: {lang_string}")

if __name__ == "__main__":
    main()
