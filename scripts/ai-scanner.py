import subprocess
import json
import os

def run_command(command, cwd=None):
    """Executes a command on the GitHub runner."""
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, shell=True)

def main():
    # 1. Search for PRs using pre-installed 'gh' CLI
    search_res = run_command('gh search prs --head "copilot/" --state open --json number,repository')
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No matching PRs found.")
        return

    prs = json.loads(search_res.stdout)

    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        
        print(f"Preparing PR #{num} from {repo} for CodeQL scan...")
        
        # 2. Checkout the PR code into a subfolder
        # The 'analyze' step in the YAML will pick up the code in the workspace
        run_command(f"gh pr checkout {num}")

if __name__ == "__main__":
    main()