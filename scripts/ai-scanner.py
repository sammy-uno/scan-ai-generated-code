import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # Get current user to exclude own PRs
    user_res = run_command('gh api user --jq .login')
    current_user = user_res.stdout.strip()

    # SEARCH QUALIFIERS:
    # head:copilot/ -> branch starts with copilot/
    # language:java -> repo must be primarily Java
    # -author:{user} -> exclude PRs created by you
    # is:public -> search only public PRs
    search_query = f'head:copilot/ language:java -author:{current_user} is:pr state:open is:public'
    search_cmd = f'gh search prs "{search_query}" --json number,repository'
    
    search_res = run_command(search_cmd)
    
    if not search_res.stdout or search_res.stdout.strip() == "[]":
        print("No matching Java PRs found from other authors.")
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        # Verify it really has Java files in the repo view
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.lower().strip().split('\n')

        if "java" in raw_langs:
            all_langs.add("java")
            run_command(f"gh pr checkout {num} --repo {repo_full_name}")

    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
