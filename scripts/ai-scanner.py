import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Search for PRs
    search_res = run_command('gh search prs --head "copilot/" --state open --json number,repository')
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No matching PRs found.")
        return

    pr = json.loads(search_res.stdout)[0]
    num = str(pr.get("number"))
    repo = pr.get("repository", {}).get("nameWithOwner")
    
    # 2. Detect Languages in the repo
    lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
    detected_langs = lang_res.stdout.lower().strip().split('\n')

    # UPDATED: Mapping strictly for Java/Kotlin
    # This prevents the Exit Code 32 error by not scanning languages without source code
    mapping = {"java": "java-kotlin"}
    to_scan = [mapping[l] for l in detected_langs if l in mapping]
    
    lang_string = ",".join(set(to_scan))
    
    # 3. Output to GitHub Actions Environment
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            # If no Java is detected, this output will be empty
            f.write(f"detected_langs={lang_string}\n")
    
    # 4. Checkout the PR
    print(f"Checking out PR #{num} from {repo}...")
    run_command(f"gh pr checkout {num}")

if __name__ == "__main__":
    main()
