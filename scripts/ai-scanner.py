import subprocess
import json
import os

def run_command(command):
    return subprocess.run(command, capture_output=True, text=True, shell=True)

def main():
    # 1. Search for PRs co-authored by Claude globally
    # We use a broad search for the attribution string
    query = 'is:pr is:open is:public "Co-Authored-By: Claude"'
    search_cmd = f'gh search prs "{query}" --limit 30 --json number,repository'
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No public Claude co-authored PRs found.")
        set_output("detected_langs", "")
        return

    prs = json.loads(search_res.stdout)
    
    # Process only the FIRST valid Java PR for this run 
    # (To scan multiple PRs, consider a Matrix Strategy or repeated runs)
    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        
        # Verify repo contains Java
        lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
        if "Java" not in lang_res.stdout:
            continue

        print(f"Targeting: {repo}#{num}")
        run_command(f"gh pr checkout {num} --repo {repo}")

        # Get changed files for targeted scan
        files_res = run_command(f"gh pr view {num} --repo {repo} --json files --jq '.files[].path'")
        java_files = [f for f in files_res.stdout.strip().split('\n') if f.endswith(('.java', '.kt'))]
        
        config_content = "paths:\n"
        for f in java_files:
            config_content += f"  - {f}\n"
        with open("codeql-config.yml", "w") as f:
            f.write(config_content)
        
        title_res = run_command(f'gh pr view {num} --repo {repo} --json title --jq ".title"')
        pr_title = title_res.stdout.strip()
        safe_title = "".join(c for c in pr_title if c.isalnum() or c in ("-", "_"))

        set_output("detected_langs", "java-kotlin")
        set_output("pr_name", safe_title)
        set_output("full_title", pr_title)
        set_output("repo_name", repo)
        return # Found a valid candidate, exit loop

def set_output(name, value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"{name}={value}\n")

if __name__ == "__main__":
    main()
