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

def main():
    print("DEBUG: Starting ai-scanner.py script...", file=sys.stderr)
    
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    # 1. Search for PRs
    search_query = 'Co-Authored-By: Claude'
    search_cmd = f'gh search prs "{search_query}" --state open --limit 5 --json number,repository,title'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("DEBUG: No PRs found matching the search query.", file=sys.stderr)
        print('matrix_data={"include":[]}')
        return

    prs = json.loads(search_res.stdout)
    
    # --- PRINT LIST OF DISCOVERED PRs ---
    print("\n=== LIST OF PRs FOUND IN SEARCH ===", file=sys.stderr)
    for i, pr in enumerate(prs, 1):
        repo = pr.get("repository", {}).get("nameWithOwner")
        num = pr.get("number")
        title = pr.get("title")
        print(f"{i}. {repo}#{num} - {title}", file=sys.stderr)
    print("===================================\n", file=sys.stderr)
    
    matrix_include = []

    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        title = pr.get("title", "Untitled")
        
        # 2. Detect languages
        lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name | ascii_downcase"')
        if lang_res.returncode != 0:
            continue

        repo_langs = lang_res.stdout.strip().split('\n')
        target_langs = [l for l in repo_langs if l in codeql_supported]
        
        for lang in target_langs:
            matrix_include.append({
                "pr_num": num,
                "repo_name": repo,
                "language": lang,
                "pr_title": title,
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}"
            })

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
