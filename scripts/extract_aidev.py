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

    filtered_df['language'] = filtered_df['language'].str.lower()
    filtered_df.loc[filtered_df['language'] == 'typescript', 'language'] = 'javascript'

    filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
    filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
    
    # 🔍 --- ENHANCED TRACE LOG MODULE FOR DATA ROUTING ---
    print("\n====================================================")
    print("🔍 DIAGNOSTIC LOG: TRACKING VALUE ASSIGNMENT ORIGIN")
    print("====================================================")
    
    if 'additions' in filtered_df.columns and 'deletions' in filtered_df.columns:
        print("🎯 [ROUTE A] Match found for raw 'additions/deletions' columns! Calculating True LOC...")
        filtered_df['pr_loc'] = (
            pd.to_numeric(filtered_df['additions'], errors='coerce').fillna(0) + 
            pd.to_numeric(filtered_df['deletions'], errors='coerce').fillna(0)
        ).astype(int)
    elif 'additions_pr' in filtered_df.columns and 'deletions_pr' in filtered_df.columns:
        print("🎯 [ROUTE B] Match found for suffixed 'additions_pr/deletions_pr' columns! Calculating True LOC...")
        filtered_df['pr_loc'] = (
            pd.to_numeric(filtered_df['additions_pr'], errors='coerce').fillna(0) + 
            pd.to_numeric(filtered_df['deletions_pr'], errors='coerce').fillna(0)
        ).astype(int)
    else:
        print("⚠️ [ROUTE C] WARNING: No code metrics found in table columns! Falling back to PR Description length...")
        print(f"Post-Merge Available Columns: {filtered_df.columns.tolist()[:15]}")
        filtered_df['body'] = filtered_df['body'].fillna('')
        filtered_df['pr_loc'] = filtered_df['body'].str.len().astype(int)
        
    print(f"📊 First 5 outputs calculated for pr_loc: {filtered_df['pr_loc'].head().tolist()}")
    print("====================================================\n")
    
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
