import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Search ALL public PRs globally with branch starting with "copilot/"
    search_cmd = 'gh search prs --head "copilot/" --state open --json number,repository'
    search_res = run_command(search_cmd)
    
    # Debug: see what the search found
    print(f"Search results: {search_res.stdout}")

    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No matching PRs found.")
        # Ensure we still write to output to avoid step errors
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    # 2. Loop through discovered PRs
    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        print(f"Checking out PR #{num} from {repo_full_name}...")
        
        # Checkout the PR code
        run_command(f"gh pr checkout {num} --repo {repo_full_name}")
        
        # Detect languages in this repo
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        detected_langs = lang_res.stdout.lower().strip().split('\n')

        # Strictly map for Java/Kotlin
        mapping = {"java": "java-kotlin"}
        for l in detected_langs:
            if l in mapping:
                all_langs.add(mapping[l])

    # 3. Finalize output
    lang_string = ",".join(all_langs)
    set_output(lang_string)
    print(f"Final detected_langs: {lang_string}")

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
