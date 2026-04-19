import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Global search for public PRs with branch "copilot/"
    search_cmd = 'gh search prs --head "copilot/" --state open --json number,repository'
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        # 2. Check languages via GitHub API
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.lower().strip().split('\n')

        # Static analysis without build works best for Java
        if any("java" in l for l in raw_langs):
            all_langs.add("java")
            # Checkout the last matching PR to scan
            run_command(f"gh pr checkout {num} --repo {repo_full_name}")

    # 3. Finalize output
    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
