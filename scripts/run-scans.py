import os
import json
import subprocess
from urllib.parse import urlparse, urlunparse

def run_cmd(cmd, timeout_secs=300):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_secs)
        if res.returncode != 0:
            print(f"Command failed with return code {res.returncode}")
            print(f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        return res.returncode
    except subprocess.TimeoutExpired:
        print(f"🛑 CRITICAL: Command timed out after {timeout_secs} seconds.")
        return -1

def main():
    raw_json = os.environ.get("RAW_MATRIX_JSON", "{}")
    gh_token = os.environ.get("GH_TOKEN", "")
    codeql_bin = os.environ.get("CODEQL_BIN", "codeql")
    
    try:
        matrix_data = json.loads(raw_json)
    except Exception:
        print("Error: Invalid Matrix JSON payload structure.")
        return

    items = matrix_data.get("include", [])
    print(f"Starting sequential execution for {len(items)} repositories...")

    for item in items:
        repo = item.get("repo_name", "").strip()
        pr = item.get("pr_num", "").strip()
        lang = item.get("language", "").strip()
        agent = item.get("agent_name", "").strip()
        
        if not repo or not pr:
            continue
            
        safe_repo = repo.replace("/", "_SLASH_")

        print(f"\n==========================================")
        print(f"🚀 SCANNING: {repo} (#{pr}) [{lang}]")
        print(f"==========================================")

        # 1. Clean workspace environment layout
        run_cmd("rm -rf ./target_src && mkdir -p ./target_src")
        
        # 2. Native Git clone initialization sequence
        run_cmd("cd ./target_src && git init")
        run_cmd("cd ./target_src && git config --local filter.lfs.smudge 'git-lfs smudge --skip -- %f'")
        run_cmd("cd ./target_src && git config --local filter.lfs.process 'git-lfs filter-process --skip'")

        # --- FIX: TYPE-SAFE COMPLIANT URL BUILDER ENGINE ---
        # Explicitly segments authentication components to prevent formatting errors
        netloc = f"x-access-token:{gh_token}@github.com"
        path = f"/{repo}.git"
        url_parts = ('https', netloc, path, '', '', '')
        fetch_url = urlunparse(url_parts)
        
        fetch_ref = f"refs/pull/{pr}/head:pr_{pr}"
        
        fetch_status = run_cmd(f"cd ./target_src && git fetch --depth=1 '{fetch_url}' '{fetch_ref}'", timeout_secs=120)
        
        analyze_status = -1
        if fetch_status == 0:
            run_cmd(f"cd ./target_src && git checkout 'pr_{pr}'")
            
            # Run CodeQL compile sequences directly via explicit paths
            db_status = run_cmd(f"'{codeql_bin}' database create './codeql_db_{safe_repo}' --language='{lang}' --source-root=./target_src --overwrite", timeout_secs=300)
            
            if db_status == 0:
                analyze_status = run_cmd(f"'{codeql_bin}' database analyze './codeql_db_{safe_repo}' --format=sarif-latest --output='./{safe_repo}--{pr}--{lang}--{agent}.sarif'", timeout_secs=300)

        # 5. Drop state artifacts tracking markers based on execution outcome
        if analyze_status == 0 and os.path.exists(f"{safe_repo}--{pr}--{lang}--{agent}.sarif"):
            with open(f"./{safe_repo}--{pr}.success", "w") as f_ok:
                f_ok.write("success")
            print(f"✅ SUCCESS: {repo} (#{pr})")
        else:
            with open(f"./{safe_repo}--{pr}.failed", "w") as f_ko:
                f_ko.write("failed")
            print(f"⚠️ TIMEOUT/FAIL: {repo} (#{pr}) - Isolated cleanly")

if __name__ == "__main__":
    main()
