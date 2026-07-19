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

    # --- CHRONOLOGICAL SORT & PR LOC COMPUTATION MODULE ---
    filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
    filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
    
    # 🚀 CRITICAL SUEFIX FIX: Target the exact merged column names ('additions_pr' and 'deletions_pr')
    add_col = 'additions_pr' if 'additions_pr' in filtered_df.columns else ('additions' if 'additions' in filtered_df.columns else None)
    del_col = 'deletions_pr' if 'deletions_pr' in filtered_df.columns else ('deletions' if 'deletions' in filtered_df.columns else None)
    
    if add_col and del_col:
        filtered_df['pr_loc'] = (
            pd.to_numeric(filtered_df[add_col], errors='coerce').fillna(0) + 
            pd.to_numeric(filtered_df[del_col], errors='coerce').fillna(0)
        ).astype(int)
    else:
        # Safe structural fallback to prevent breaking matrix pipelines if properties are omitted
        filtered_df['pr_loc'] = 0
    
    scan_limit = 500
    final_list = filtered_df.head(scan_limit)

    # Select, rearrange, and rename columns for the scanner matrix
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
