import subprocess
import json
import os

def run_command(command):
    # shell=True handles complex CLI queries correctly
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def is_code_scanning_enabled(repo):
    """
    Checks if Code Scanning is available for the repository.
    Returns True if we can query the default setup or alerts endpoint.
    """
    # Attempt 1: Check Default Setup configuration
    cmd_setup = f'gh api repos/{repo}/code-scanning/default-setup --silent'
    res_setup = run_command(cmd_setup)
    if res_setup.returncode == 0:
        return True
        
    # Attempt 2: Check Alerts endpoint (Success if 200, even if list is empty [])
    # If this returns 403, GitHub Advanced Security is likely disabled for private repos.
    cmd_alerts = f'gh api repos/{repo}/code-scanning/alerts?per_page=1 --silent'
    res_alerts = run_command(cmd_alerts)
    return res_alerts.returncode == 0

def main():
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    # Robust search query to catch AI attribution
    search_query = 'Co-Authored-By: Claude'
    search_cmd = f'gh search prs "{search_query}" --state open --limit 5 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    matrix_include = []

    if search_res.returncode == 0 and search_res.stdout.strip() != "[]":
        prs = json.loads(search_res.stdout)
        for pr in prs:
            num = str(pr.get("number"))
            repo = pr.get("repository", {}).get("nameWithOwner")
            
            # Use the more resilient check
            if not is_code_scanning_enabled(repo):
                # Output detail to logs for troubleshooting
                print(f"Skipping {repo}: Code Scanning check failed (API returned non-200).")
                continue
            
            # Detect languages supported by CodeQL
            lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name | ascii_downcase"')
            repo_langs = lang_res.stdout.strip().split('\n')
            target_langs = [l for l in repo_langs if l in codeql_supported]
            
            for lang in target_langs:
                matrix_include.append({
                    "pr_num": num,
                    "repo_name": repo,
                    "language": lang,
                    "pr_title": pr.get("title", "Untitled"),
                    "category_name": f"{repo.split('/')[-1]}-{num}-{lang}"
                })

    # Always output a valid JSON structure for the matrix
    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(output)

if __name__ == "__main__":
    main()
