import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    # Load PRs and Repository metadata
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

    # Debug: Print columns to log so you can verify them if it fails again
    print(f"PR Columns: {pr_df.columns.tolist()}")
    print(f"Repo Columns: {repo_df.columns.tolist()}")

    # Determine the correct join key (usually 'repo_name' in PR and something else in Repo)
    # Most AIDev versions use 'repo_name' in pull_request.parquet
    # and 'repo_name' or 'full_name' in repository.parquet
    pr_key = 'repo_name' if 'repo_name' in pr_df.columns else 'repository_name'
    repo_key = 'repo_name' if 'repo_name' in repo_df.columns else 'name_with_owner'
    
    if repo_key not in repo_df.columns:
        # Fallback for some AIDev versions where it might just be 'name'
        repo_key = 'name' if 'name' in repo_df.columns else repo_df.columns[0]

    print(f"Joining on PR.{pr_key} and Repo.{repo_key}...")
    
    # Join tables using the identified keys
    merged_df = pd.merge(pr_df, repo_df, left_on=pr_key, right_on=repo_key, how='inner')

    # Filter by stars, agentic status, and language
    supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
    
    # Star count column is usually 'stargazers_count' or 'stars'
    star_col = 'stargazers_count' if 'stargazers_count' in merged_df.columns else 'stars'
    lang_col = 'primary_language' if 'primary_language' in merged_df.columns else 'language'

    filtered_df = merged_df[
        (merged_df[star_col] > 100) &
        (merged_df[lang_col].isin(supported_langs)) &
        (merged_df['is_agentic'] == True)
    ].copy()

    # Normalize language names for CodeQL
    filtered_df[lang_col] = filtered_df[lang_col].str.lower()
    filtered_df.loc[filtered_df[lang_col] == 'typescript', lang_col] = 'javascript'

    # Select and rename columns to match what your scanner expects
    scan_list = filtered_df[[pr_key, 'number', 'title', lang_col, 'agent_name']].rename(columns={
        pr_key: 'repo_name',
        lang_col: 'primary_language'
    })
    
    scan_list.to_csv("aidev_scan_list.csv", index=False)
    print(f"Success: Created aidev_scan_list.csv with {len(scan_list)} entries.")

if __name__ == "__main__":
    extract_data()
