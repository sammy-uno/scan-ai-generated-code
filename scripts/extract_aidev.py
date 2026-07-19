import pandas as pd
import os

def extract_data():
    print("Streaming AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")
    
    print("📥 Loading Granular File Changes Table...")
    # This table holds the true additions and deletions line counts for each PR file
    file_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request_file.parquet")

    # Group file modifications by PR ID to compute the total LOC changed per PR
    print("Aggregating line changes by PR...")
    file_loc = file_df.groupby('pull_request_id')[['additions', 'deletions']].sum().reset_index()
    file_loc['true_loc'] = file_loc['additions'] + file_loc['deletions']

    print("Joining Metadata layers...")
    merged_meta = pd.merge(
        pr_df, 
        repo_df, 
        left_on='repo_id', 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )
    
    print("Chaining file-level True LOC metrics...")
    # Join the accumulated file line counts directly to the PR data frame via matching IDs
    merged_df = pd.merge(
        merged_meta,
        file_loc,
        left_on='id_pr',
        right_on='pull_request_id',
        how='inner'
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
    
    # Map the compiled lines-of-code directly to your target key
    filtered_df['pr_loc'] = filtered_df['true_loc'].astype(int)
    
    scan_limit = 500
    final_list = filtered_df.head(scan_limit)

    scan_list = final_list[['full_name', 'number', 'title', 'language', 'agent', 'stars', 'pr_loc']].rename(columns={
        'full_name': 'repo_name',
        'language': 'primary_language',
        'agent': 'agent_name',
        'stars': 'repo_stars'
    })
    
    scan_list.to_csv("aidev_scan_list.csv", index=False)
    print(f"Success! Created aidev_scan_list.csv with actual physical lines-of-code metrics.")

if __name__ == "__main__":
    extract_data()
