import subprocess
import json
import os

def run_command(command):
    # shell=True is essential for parsing nested quotes in CLI strings
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def is_code_scanning_enabled(repo):
    """
    Checks if Code Scanning is enabled by attempting to list alerts.
    If disabled, GitHub returns a 403 or non-zero status code.
    """
    cmd = f'gh api repos/{repo}/code-scanning/alerts?per_page=1 --silent'
    res = run_command(cmd)
    return res.returncode == 0

def main():
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    # Using a robust search string to ensure variations in trailers are caught
    search_query = 'Co-Authored-By: Claude'
    search_cmd = f'gh search prs "{search_query}" --state open --limit 5 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    matrix_include = []

    if search_res.returncode == 0 and search_res.stdout.strip() != "[]":
        prs = json.loads(search_res.stdout)
        for pr in prs:
            num = str(pr.get("number"))
            repo = pr.get("repository", {}).get("nameWithOwner")
            
            # Skip if we cannot upload security results
            if not is_code_scanning_enabled(repo):
                print(f"Skipping {repo}: Code Scanning not active.")
                continue
            
            # Detect languages in the repo
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

    # Always output a valid JSON structure
    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(output)

if __name__ == "__main__":
    main()
