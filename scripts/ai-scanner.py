import subprocess
import os

def run_command(command):
    return subprocess.run(command, capture_output=True, text=True, shell=True)

def main():
    repo = "apache/rocketmq"
    pr_num = "9175"

    print(f"Targeting PR: {repo}#{pr_num}")
    
    # 1. Checkout PR
    run_command(f"gh pr checkout {pr_num} --repo {repo}")

    # 2. Get changed files and create CodeQL config
    files_res = run_command(f"gh pr view {pr_num} --repo {repo} --json files --jq '.files[].path'")
    changed_files = files_res.stdout.strip().split('\n')

    # Filter for Java files and create config content
    java_files = [f for f in changed_files if f.endswith(('.java', '.kt'))]
    
    config_content = "paths:\n"
    if java_files:
        for f in java_files:
            config_content += f"  - {f}\n"
    else:
        # If no Java files, include nothing to avoid scanning whole repo
        config_content += "  - 'non-existent-path-to-filter-all'\n"

    with open("codeql-config.yml", "w") as f:
        f.write(config_content)
    
    # 3. Get PR Title for naming
    title_res = run_command(f'gh pr view {pr_num} --repo {repo} --json title --jq ".title"')
    pr_title = title_res.stdout.strip()
    safe_title = "".join(c for c in pr_title if c.isalnum() or c in ("-", "_"))

    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs=java-kotlin\n")
            f.write(f"pr_name={safe_title}\n")
            f.write(f"full_title={pr_title}\n")

if __name__ == "__main__":
    main()
