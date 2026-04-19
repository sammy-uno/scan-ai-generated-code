import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Search PRs
    search_cmd = 'gh search prs --head "copilot/" --state open --json number,repository'
    search_res = run_command(search_cmd)
    
    # DEBUG: See what the search actually found
    print(f"SEARCH STDOUT: {search_res.stdout}")
    print(f"SEARCH STDERR: {search_res.stderr}")

    if not search_res.stdout or search_res.stdout.strip() == "[]":
        set_output("")
        return

    prs = json.loads(search_res.stdout)
    all_langs = set()

    for pr in prs:
        num = str(pr.get("number"))
        repo_full_name = pr.get("repository", {}).get("nameWithOwner")
        
        # 2. Get languages BEFORE checking out to verify detection
        lang_res = run_command(f'gh repo view {repo_full_name} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.strip().split('\n')
        print(f"Repo {repo_full_name} contains: {raw_langs}")

        mapping = {"java": "java-kotlin"}
        for l in raw_langs:
            clean_l = l.lower().strip()
            if clean_l in mapping:
                all_langs.add(mapping[clean_l])

    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
