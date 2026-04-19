import subprocess
import json
import os

def run_command(command):
    # Capture output for processing and error reporting
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def set_output(value):
    # Writes variables to the GitHub Actions output file
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

def main():
    # Define keywords used by common AI agents
    keywords = ["copilot", "sweep", "coderabbit", "pixee"]
    found_any = False

    for kw in keywords:
        print(f"Searching globally for AI keyword: {kw}")
        # Global search for open public PRs
        cmd = f'gh search prs "{kw}" --state open --is-public --limit 10 --json number,repository'
        res = run_command(cmd)
        
        if res.stdout and res.stdout.strip() != "[]":
            prs = json.loads(res.stdout)
            for pr in prs:
                num = str(pr.get("number"))
                repo = pr.get("repository", {}).get("nameWithOwner")
                
                # Verify the repository is recognized as containing Java
                lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
                raw_langs = lang_res.stdout.lower()

                if "java" in raw_langs:
                    print(f"MATCH: {repo} (PR #{num}) has Java. Checking out for scan...")
                    # Checkout the target PR into the current runner workspace
                    run_command(f"gh pr checkout {num} --repo {repo}")
                    set_output("java")
                    found_any = True
                    return 

    if not found_any:
        print("No public AI-agent Java PRs found. Ensure your PAT has 'public_repo' scope.")
        set_output("")

if __name__ == "__main__":
    main()
