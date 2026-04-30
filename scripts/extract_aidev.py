import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

    print(f"Joining {len(pr_df)} PRs with repository metadata...")
    merged_df = pd.merge(pr_df, repo_df, on='repo_name', how='inner')
    
    supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
    
    filtered_df = merged_df[
        (merged_df['stargazers_count'] > 100) &
        (merged_df['primary_language'].isin(supported_langs)) &
        (merged_df['is_agentic'] == True)
    ].copy()

    filtered_df['primary_language'] = filtered_df['primary_language'].str.lower()
    filtered_df.loc[filtered_df['primary_language'] == 'typescript', 'primary_language'] = 'javascript'

    scan_list = filtered_df[['repo_name', 'number', 'title', 'primary_language', 'agent_name']]
    
    # Save to the project root
    scan_list.to_csv("aidev_scan_list.csv", index=False)
    print(f"Success: Created aidev_scan_list.csv with {len(scan_list)} entries.")

if __name__ == "__main__":
    extract_data()
