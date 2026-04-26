import subprocess
import json
import os

def run_command(command):
    return subprocess.run(command, capture_output=True, text=True, shell=True)

def is_code_scanning_enabled(repo):
    """Checks eligibility for Code Scanning and logs specific error codes on failure."""
    # Canary check: list alerts (Success if 200, even if list is empty [])
    cmd = f'gh api repos/{repo}/code-scanning/alerts?per_page=1 --silent'
    res = run_command(cmd)
    
    if res.returncode != 0:
        # Debugging: Get the actual status code if the check fails
        debug_res = run_command(f'gh api repos/{repo}/code-scanning/alerts --include')
        status_line = next((line for line in debug_res.stdout.split('\n') if "HTTP/" in line), "Unknown")
        print(f"DEBUG: {repo} failed with {status_line}")
        return False
    return True

def main():
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    search_cmd = 'gh search prs "Co-Authored-By: Claude" --state open --limit 5 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    matrix_include = []
    if search_res.returncode == 0:
        prs = json.loads(search_res.stdout)
        for pr in prs:
            num, repo = str(pr.get("number")), pr.get("repository", {}).get("nameWithOwner")
            
            if not is_code_scanning_enabled(repo):
                print(f"Skipping {repo}: Code Scanning check failed.")
                continue
            
            lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name | ascii_downcase"')
            repo_langs = lang_res.stdout.strip().split('\n')
            target_langs = [l for l in repo_langs if l in codeql_supported]
            
            for lang in target_langs:
                matrix_include.append({
                    "pr_num": num, "repo_name": repo, "language": lang,
                    "pr_title": pr.get("title"), "category_name": f"{repo.split('/')[-1]}-{num}-{lang}"
                })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
