import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def is_code_scanning_enabled(repo):
    cmd = f'gh api repos/{repo}/code-scanning/alerts?per_page=1 --silent'
    res = run_command(cmd)
    return res.returncode == 0

def main():
    codeql_supported = ["java", "javascript", "python", "go", "ruby", "csharp", "cpp", "swift"]
    query = '"Co-Authored-By: Claude" --state open --visibility public'
    search_cmd = f'gh search prs {query} --limit 30 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    prs = json.loads(search_res.stdout)
    matrix_include = []

    for pr in prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        
        if not is_code_scanning_enabled(repo):
            continue
        
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

    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")

if __name__ == "__main__":
    main()
