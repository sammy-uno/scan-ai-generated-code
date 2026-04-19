import subprocess
import os

def run_command(command):
    # shell=True ensures parsing works correctly on all platforms
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # HARDCODED TEST DATA
    # Repository: apache/rocketmq
    # Pull Request Number: 9175
    repo = "apache/rocketmq"
    pr_num = "9175"

    print(f"Targeting specific test PR: {repo}#{pr_num}")
    
    # 1. Checkout the specific public PR
    # This replaces the need for 'gh search' during this test phase
    checkout_res = run_command(f"gh pr checkout {pr_num} --repo {repo}")
    
    if checkout_res.returncode != 0:
        print(f"Checkout failed: {checkout_res.stderr}")
        set_output("")
        return

    # 2. Confirm the checked-out PR contains Java
    lang_res = run_command(f'gh repo view {repo} --json languages --jq ".languages[].node.name"')
    if "Java" in lang_res.stdout:
        print(f"Verified Java in {repo}. Staging for CodeQL...")
        set_output("java-kotlin")
    else:
        print("Java not detected in this repository.")
        set_output("")

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
