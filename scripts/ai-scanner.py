import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # Search for PRs with specific attribution
    query = '"Co-Authored-By: Claude" --state open --visibility public'
    search_cmd = f'gh search prs {query} --limit 30 --json number,repository,title'
    search_res = run_command(search_cmd)
    
    matrix_include = []

    if search_res.stdout and search_res.stdout.strip() != "[]":
        prs = json.loads(search_res.stdout)
        for pr in prs:
            num = str(pr.get("number"))
            repo = pr.get("repository", {}).get("nameWithOwner")
            title = pr.get("title", "Untitled PR")
            
            # Check for Java/Kotlin
            lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
            if any(lang in lang_res.stdout for lang in ["Java", "Kotlin"]):
                # Clean title for category name
                safe_title = "".join(c for c in title if c.isalnum() or c in ("-", "_"))[:50]
                
                matrix_include.append({
                    "pr_num": num,
                    "repo_name": repo,
                    "pr_title": title,
                    "category_name": f"{repo.split('/')[-1]}-{num}"
                })

    # Output the matrix for GitHub Actions
    output = json.dumps({"include": matrix_include})
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"matrix_data={output}\n")
    else:
        print(output)

if __name__ == "__main__":
    main()
