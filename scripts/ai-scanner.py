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

def get_changed_paths(repo, pr_num):
    """Returns a list of top-level directories changed in the PR."""
    # Fetch filenames changed in the PR
    cmd = f'gh pr diff {pr_num} --repo {repo} --name-only'
    res = run_command(cmd)
    if res.returncode != 0:
        return ["."] # Fallback to root if diff fails
    
    files = res.stdout.strip().split('\n')
    # Get unique top-level directories (e.g. 'drools-core/src/...' -> 'drools-core')
    # We use a set to avoid duplicates
    paths = set()
    for f in files:
        if '/' in f:
            paths.add(f.split('/')[0])
        else:
            paths.add(".") # File is in the root
            
    return list(paths)

def main():
    print("DEBUG: Starting ai-scanner.py script...", file=sys.stderr)
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    search_query = 'Co-Authored-By: Claude'
    search_cmd = f'gh search prs "{search_query}" --state open --limit 5 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print('matrix_data={"include":[]}')
        return

    prs = json.loads(search_res.stdout)
    matrix_include = []

    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        title = pr.get("title", "Untitled")
        
        # New: Get the specific folders changed in this PR
        changed_folders = get_changed_paths(repo, num)
        print(f"DEBUG: PR {repo}#{num} found changes in: {changed_folders}", file=sys.stderr)

        lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name | ascii_downcase"')
        if lang_res.returncode != 0: continue

        repo_langs = lang_res.stdout.strip().split('\n')
        target_langs = [l for l in repo_langs if l in codeql_supported]
        
        for lang in target_langs:
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": title,
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}",
                # New: Pass paths as a newline-separated string for CodeQL
                "scan_paths": "\n".join(changed_folders)
            })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
