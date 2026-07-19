import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

    print("Joining tables on PR.repo_id and Repo.id...")
    merged_df = pd.merge(
        pr_df, 
        repo_df, 
        left_on='repo_id', 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )

    supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
    
    filtered_df = merged_df[
        (merged_df['stars'] > 500) &
        (merged_df['language'].isin(supported_langs)) &
        (merged_df['agent'].notna())
    ].copy()

    # Normalize language names
    filtered_df['language'] = filtered_df['language'].str.lower()
    filtered_df.loc[filtered_df['language'] == 'typescript', 'language'] = 'javascript'

    # --- CHRONOLOGICAL SORT & SAFE LOC COMPUTATION MODULE ---
    filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
    filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
    
    # 🚀 SAFE DICTIONARY RESOLVER: Completely eliminates KeyErrors by verifying schema shapes
    adds = filtered_df['additions'] if 'additions' in filtered_df.columns else (filtered_df['addition'] if 'addition' in filtered_df.columns else 0)
    dels = filtered_df['deletions'] if 'deletions' in filtered_df.columns else (filtered_df['deletion'] if 'deletion' in filtered_df.columns else 0)
    
    filtered_df['pr_loc'] = (
        pd.to_numeric(adds, errors='coerce').fillna(0) + 
        pd.to_numeric(dels, errors='coerce').fillna(0)
    ).astype(int)
    
    scan_limit = 500
    final_list = filtered_df.head(scan_limit)

    # Selected and appended 'pr_loc' alongside 'stars' mapping
    scan_list = final_list[['full_name', 'number', 'title', 'language', 'agent', 'stars', 'pr_loc']].rename(columns={
        'full_name': 'repo_name',
        'language': 'primary_language',
        'agent': 'agent_name',
        'stars': 'repo_stars'
    })
    
    scan_list.to_csv("aidev_scan_list.csv", index=False)
    print(f"Success: Created aidev_scan_list.csv with {len(scan_list)} entries.")

if __name__ == "__main__":
    extract_data()
