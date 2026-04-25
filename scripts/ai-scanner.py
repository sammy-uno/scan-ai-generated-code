import subprocess
import json
import os

def run_command(command):
    # shell=True is essential for correctly parsing quotes in Windows/Linux
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def set_output(name, value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"{name}={value}\n")

def main():
    # Exact query you validated locally
    # We add a limit to keep the run efficient
    query = '"Co-Authored-By: Claude" --state open --visibility public'
    search_cmd = f'gh search prs {query} --limit 30 --json number,repository'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No matches found for the AI attribution string.")
        set_output("detected_langs", "")
        return

    prs = json.loads(search_res.stdout)
    
    # Iterate to find the first Java project
    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        
        # Verify repo contains Java/Kotlin
        lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
        if not any(lang in lang_res.stdout for lang in ["Java", "Kotlin"]):
            continue

        print(f"Targeting Claude-authored PR: {repo}#{num}")
        
        # 1. Checkout PR
        run_command(f"gh pr checkout {num} --repo {repo}")

        # 2. Identify changed Java files for targeted scan
        files_res = run_command(f"gh pr view {num} --repo {repo} --json files --jq '.files[].path'")
        java_files = [f for f in files_res.stdout.strip().split('\n') if f.endswith(('.java', '.kt'))]
        
        # 3. Create dynamic CodeQL config
        config_content = "paths:\n"
        for f in java_files:
            config_content += f"  - {f}\n"
        with open("codeql-config.yml", "w") as f:
            f.write(config_content)
        
        # 4. Get PR metadata for summary
        title_res = run_command(f'gh pr view {num} --repo {repo} --json title --jq ".title"')
        pr_title = title_res.stdout.strip()
        safe_title = "".join(c for c in pr_title if c.isalnum() or c in ("-", "_"))

        set_output("detected_langs", "java-kotlin")
        set_output("pr_name", safe_title)
        set_output("full_title", pr_title)
        set_output("repo_name", repo)
        return # Process one valid Java PR per run

if __name__ == "__main__":
    main()
