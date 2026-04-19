import subprocess
import json
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # 1. Broad keyword search for PRs likely from AI agents
    # Keywords often found in AI-generated PR titles, branches, or bodies
    keywords = ["copilot", "sweep", "coderabbit", "pixee", "qodo"]
    all_prs = []

    for kw in keywords:
        print(f"Searching for keyword: {kw}")
        # Search globally for open public PRs with this keyword
        cmd = f'gh search prs "{kw}" --state open --is-public --limit 30 --json number,repository,author'
        res = run_command(cmd)
        if res.stdout:
            try:
                all_prs.extend(json.loads(res.stdout))
            except json.JSONDecodeError:
                continue

    if not all_prs:
        print("No public PR candidates found.")
        set_output("")
        return

    # Use a set to avoid processing the same PR multiple times
    seen_prs = set()
    all_langs = set()

    # 2. Filter for Java and actual AI bots
    for pr in all_prs:
        num = str(pr.get("number"))
        repo = pr.get("repository", {}).get("nameWithOwner")
        author = pr.get("author", {}).get("login", "").lower()
        
        pr_id = f"{repo}#{num}"
        if pr_id in seen_prs:
            continue
        seen_prs.add(pr_id)

        # Check for Java in the repository
        lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
        raw_langs = lang_res.stdout.lower().strip().split('\n')

        if any("java" in l for l in raw_langs):
            print(f"Match found: {repo} (PR #{num}) by {author}")
            all_langs.add("java")
            # Checkout the PR for scanning
            run_command(f"gh pr checkout {num} --repo {repo}")
            break # CodeQL will scan this checked-out state

    lang_string = ",".join(all_langs)
    set_output(lang_string)

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
