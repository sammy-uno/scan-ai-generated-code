import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")
    
    print("📥 Loading Granular File Sizing Table: pull_request_file.parquet...")
    try:
        # Corrected dataset folder layout reference path
        file_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request_file.parquet")
        print("Aggregating lines-of-code changes by unique pull request IDs...")
        loc_grouped = file_df.groupby('pull_request_id')[['additions', 'deletions']].sum().reset_index()
        loc_grouped['true_loc'] = loc_grouped['additions'] + loc_grouped['deletions']
    except Exception as e:
        print(f"⚠️ Sizing table layer fetch error: {e}")
        loc_grouped = pd.DataFrame(columns=['pull_request_id', 'true_loc'])

    print("Joining metadata layers on PR.repo_id and Repo.id...")
    merged_meta = pd.merge(
        pr_df, 
        repo_df, 
        left_on='repo_id', 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )
    
    print("Merging accumulated line change metrics into core dataset matrix...")
    if not loc_grouped.empty:
        merged_df = pd.merge(
            merged_meta,
            loc_grouped,
            left_on='id_pr',
            right_on='pull_request_id',
            how='inner'
        )
    else:
        merged_df = merged_meta.copy()

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
    
    print("\n====================================================")
    print("🔍 DIAGNOSTIC LOG: TRACKING VALUE ASSIGNMENT ORIGIN")
    print("====================================================")
    
    if 'true_loc' in filtered_df.columns and not filtered_df['true_loc'].isna().all():
        print("🎯 [ROUTE A] Successfully linked file changes! Populating True LOC...")
        filtered_df['pr_loc'] = filtered_df['true_loc'].fillna(0).astype(int)
    else:
        print("⚠️ [ROUTE B] Sizing matrix could not link. Defaulting to PR character count approximation...")
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
