import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")
    task_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_task_type.parquet")

    # --- 🔍 DEBUG LOGS: STAGE 1 (BASE SCHEMAS) ---
    print("\n=== 🔍 DEBUG LOGS: BASE TABLE SCHEMAS ===")
    print(f"PR Table Columns:   {pr_df.columns.tolist()[:8]}")
    print(f"Repo Table Columns: {repo_df.columns.tolist()[:8]}")
    print(f"Task Table Columns: {task_df.columns.tolist()[:8]}")
    print("==========================================\n")

    print("Executing join chain across Metadata and Task Sizing layers...")
    merged_meta = pd.merge(
        pr_df, 
        repo_df, 
        left_on='repo_id', 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )
    
    merged_df = pd.merge(
        merged_meta,
        task_df,
        left_on='id_pr',
        right_on='id',
        how='inner',
        suffixes=('', '_task')
    )

    # --- 🔍 DEBUG LOGS: STAGE 2 (POST-MERGE SCHEMAS) ---
    print("\n=== 🔍 DEBUG LOGS: POST-MERGE JONED TABLE SCHEMA ===")
    print(f"Merged Dataset Columns: {merged_df.columns.tolist()}")
    print("====================================================\n")

    supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
    filtered_df = merged_df[
        (merged_df['stars'] > 500) &
        (merged_df['language'].isin(supported_langs)) &
        (merged_df['agent'].notna())
    ].copy()

    filtered_df['language'] = filtered_df['language'].str.lower()
    filtered_df.loc[filtered_df['language'] == 'typescript', 'language'] = 'javascript'

    filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
    filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
    
    # --- EXPANDED MATCHER: SCANS BOTH PLURAL, SINGULAR, AND SUFFIX VARIANTS ---
    add_col = None
    for col in ['additions', 'addition', 'additions_task', 'addition_task', 'add_lines', 'additions_pr']:
        if col in filtered_df.columns:
            add_col = col
            break
            
    del_col = None
    for col in ['deletions', 'deletion', 'deletions_task', 'deletion_task', 'del_lines', 'deletions_pr']:
        if col in filtered_df.columns:
            del_col = col
            break
            
    print(f"⚙️ Selected Mapping Keys -> Addition: [{add_col}] | Deletion: [{del_col}]")
    
    if add_col and del_col:
        filtered_df['pr_loc'] = (
            pd.to_numeric(filtered_df[add_col], errors='coerce').fillna(0) + 
            pd.to_numeric(filtered_df[del_col], errors='coerce').fillna(0)
        ).astype(int)
    else:
        filtered_df['pr_loc'] = 0
        
    # Print the first few calculated non-zero values to verify live console health
    print(f"📊 Live Data Slicing Verification Check (First 5 values): {filtered_df['pr_loc'].head().tolist()}")
    
    scan_limit = 500
    final_list = filtered_df.head(scan_limit)

    scan_list = final_list[['full_name', 'number', 'title', 'language', 'agent', 'stars', 'pr_loc']].rename(columns={
        'full_name': 'repo_name',
        'language': 'primary_language',
        'agent': 'agent_name',
        'stars': 'repo_stars'
    })
    
    scan_list.to_csv("aidev_scan_list.csv", index=False)
    print(f"Success: Created aidev_scan_list.csv.")

if __name__ == "__main__":
    extract_data()
