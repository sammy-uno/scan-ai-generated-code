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
    print("DEBUG: Searching for AI-authored PRs on popular repos (>10 stars)...", file=sys.stderr)
    
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    
    # 1. Search for PRs with the Claude trailer on repos with >10 stars
    search_query = 'Co-Authored-By: Claude'
    # Adding --stars qualifier to the gh search command
    search_cmd = f'gh search prs "{search_query}" --state open --stars ">10" --limit 50 --json number,repository,title'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("DEBUG: No PRs found matching the search criteria.", file=sys.stderr)
        print('matrix_data={"include":[]}')
        return

    prs = json.loads(search_res.stdout)
    print(f"DEBUG: Found {len(prs)} PRs on popular repositories. Building matrix...", file=sys.stderr)
    
    matrix_include = []

    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        title = pr.get("title", "Untitled")
        
        # 2. Filter by language to ensure CodeQL compatibility
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
                "category_name": f"{repo.split('/')[-1]}-{num}-{lang}"
            })

    # Final Matrix Output for GitHub Actions
    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(f"matrix_data={output}")

if __name__ == "__main__":
    main()
