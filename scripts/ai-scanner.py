import subprocess
import os
import json

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    repo = "apache/rocketmq"
    pr_num = "9175"

    print(f"Targeting test PR: {repo}#{pr_num}")
    
    # 1. Checkout the public PR
    checkout_res = run_command(f"gh pr checkout {pr_num} --repo {repo}")
    if checkout_res.returncode != 0:
        print(f"Checkout failed: {checkout_res.stderr}")
        set_output("detected_langs", "")
        return

    # 2. Get the PR Title for naming
    title_res = run_command(f'gh pr view {pr_num} --repo {repo} --json title --jq ".title"')
    pr_title = title_res.stdout.strip()
    # Sanitize title for YAML/Category safety
    safe_title = "".join(c for c in pr_title if c.isalnum() or c in ("-", "_")).strip()

    print(f"Staging scan for: {pr_title}")
    set_output("detected_langs", "java-kotlin")
    set_output("pr_name", safe_title)
    set_output("full_title", pr_title)

def set_output(name, value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"{name}={value}\n")

if __name__ == "__main__":
    main()
