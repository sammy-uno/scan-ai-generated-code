import subprocess
import os

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result

def main():
    # Hardcoded test: Apache RocketMQ is a 100% Java repo
    repo = "apache/rocketmq"
    pr_num = "9175"

    print(f"Targeting test PR: {repo}#{pr_num}")
    
    # Checkout the public PR
    checkout_res = run_command(f"gh pr checkout {pr_num} --repo {repo}")
    
    if checkout_res.returncode != 0:
        print(f"Checkout failed: {checkout_res.stderr}")
        set_output("")
        return

    # Set output to java-kotlin for the next step
    print("Staging Java for CodeQL scan...")
    set_output("java-kotlin")

def set_output(value):
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"detected_langs={value}\n")

if __name__ == "__main__":
    main()
