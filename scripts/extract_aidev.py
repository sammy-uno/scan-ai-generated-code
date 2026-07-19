import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")
    task_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_task_type.parquet")

    print("Executing join chain across Metadata and Task Sizing layers...")
    # Step A: Combine PR values with repository popularity star metrics
    merged_meta = pd.merge(
        pr_df, 
        repo_df, 
        left_on='repo_id', 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )
    
    # 🚀 CRITICAL FIX: Match the suffixed 'id_pr' column to the task_df's 'id' column
    merged_df = pd.merge(
        merged_meta,
        task_df,
        left_on='id_pr',
        right_on='id',
        how='inner',
        suffixes=('', '_task')
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

    # --- CHRONOLOGICAL SORT & PR LOC EXTRACTION MODULE ---
    filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
    filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
    
    # Extract total lines of code changed using the task table metrics
    add_col = 'additions' if 'additions' in filtered_df.columns else ('addition' if 'addition' in filtered_df.columns else None)
    del_col = 'deletions' if 'deletions' in filtered_df.columns else ('deletion' if 'deletion' in filtered_df.columns else None)
    
    if add_col and del_col:
        filtered_df['pr_loc'] = (
            pd.to_numeric(filtered_df[add_col], errors='coerce').fillna(0) + 
            pd.to_numeric(filtered_df[del_col], errors='coerce').fillna(0)
        ).astype(int)
    else:
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
    print(f"Success: Created aidev_scan_list.csv with actual lines-of-code changes metrics.")

if __name__ == "__main__":
    extract_data()
