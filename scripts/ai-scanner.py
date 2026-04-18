iimport subprocess
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
    # This returns a list like ["Python", "JavaScript"]
    lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
    detected_langs = lang_res.stdout.lower().strip().split('\n')

    # Map GH names to CodeQL names
    mapping = {"python": "python", "javascript": "javascript", "typescript": "javascript", "java": "java", "c#": "csharp", "go": "go"}
    to_scan = [mapping[l] for l in detected_langs if l in mapping]
    
    # Remove duplicates and join for GitHub Actions
    lang_string = ",".join(set(to_scan))
    
    # 3. Output to GitHub Actions Environment
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={lang_string}\n")
    
    # 4. Checkout the PR
    print(f"Checking out PR #{num} from {repo}...")
    run_command(f"gh pr checkout {num}")

if __name__ == "__main__":
    main()
