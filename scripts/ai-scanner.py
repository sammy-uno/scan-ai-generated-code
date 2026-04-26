import subprocess
import json
import os
import sys

def run_command(command):
    """Executes a command and returns the result, logging errors to stderr."""
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(f"DEBUG ERROR: Command failed: {command}\nStderr: {result.stderr}", file=sys.stderr)
    return result

def is_code_scanning_enabled(repo):
    """Verifies if the PAT has permission to upload security results to the repo."""
    # We check the alerts endpoint; a 200 (even with []) means scanning is active/accessible.
    cmd = f'gh api repos/{repo}/code-scanning/alerts?per_page=1 --silent'
    res = run_command(cmd)
    if res.returncode == 0:
        return True
    
    # Detailed log for why a repo is being skipped
    print(f"DEBUG: Skipping {repo}. API check failed (likely no GHAS or missing PAT permissions).", file=sys.stderr)
    return False

def main():
    print("DEBUG: Starting ai-scanner.py script...", file=sys.stderr)
    
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    # 1. Search for PRs
    search_query = 'Co-Authored-By: Claude'
    search_cmd = f'gh search prs "{search_query}" --state open --limit 5 --json number,repository,title'
    
    print(f"DEBUG: Running search: {search_cmd}", file=sys.stderr)
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("DEBUG: No PRs found matching the search query.", file=sys.stderr)
        # Output empty matrix to avoid Action errors
        print('matrix_data={"include":[]}')
        return

    prs = json.loads(search_res.stdout)
    print(f"DEBUG: Found {len(prs)} potential PRs. Checking permissions...", file=sys.stderr)
    
    matrix_include = []

    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        title = pr.get("title", "Untitled")
        
        # 2. Check if we can actually scan this repo
        if not is_code_scanning_enabled(repo):
            continue
        
        # 3. Detect languages
        lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name | ascii_downcase"')
        repo_langs = lang_res.stdout.strip().split('\n')
        target_langs = [l for l in repo_langs if l in codeql_supported]
        
        print(f"DEBUG: PR {repo}#{num} has supported languages: {target_langs}", file=sys.stderr)
        
        for lang in target_langs:
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": title,
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}"
            })

    # Final Matrix Output
    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        # Fallback for local testing or unexpected environments
        print(f"matrix_data={output}")
    
    print(f"DEBUG: Successfully generated matrix with {len(matrix_include)} scan jobs.", file=sys.stderr)

if __name__ == "__main__":
    main()
