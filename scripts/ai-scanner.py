import subprocess
import json
import os

def run_command(command):
    # shell=True is critical for cross-platform quote handling
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # Strategy: Use broad keywords found in AI-generated PR titles or bodies
    # This avoids the 'head:' prefix which often fails in global search
    keywords = ["copilot", "sweepai", "coderabbit"]
    found_any = False

    for kw in keywords:
        print(f"Global keyword search: {kw}")
        # Search for open public PRs with the keyword and Java language
        cmd = f'gh search prs "{kw} language:java" --state open --visibility public --limit 10 --json number,repository'
        res = run_command(cmd)
        
        if res.stdout and res.stdout.strip() != "[]":
            try:
                prs = json.loads(res.stdout)
                for pr in prs:
                    num = str(pr.get("number"))
                    repo = pr.get("repository", {}).get("nameWithOwner")
                    
                    print(f"MATCH: {repo} (PR #{num}) found. Checking out...")
                    # Checkout using explicit repo to avoid workspace mismatch
                    checkout_res = run_command(f"gh pr checkout {num} --repo {repo}")
                    
                    if checkout_res.returncode == 0:
                        set_output("java")
                        found_any = True
                        return # Exit once a valid Java PR is staged
            except Exception as e:
                print(f"Error parsing results: {e}")

    if not found_any:
        print("Search returned zero matches. Check PAT and global rate limits.")
        set_output("")

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
