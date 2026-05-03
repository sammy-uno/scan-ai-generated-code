import pandas as pd

def extract_human_data():
    print("Streaming Human AIDev tables from Hugging Face...")
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/human_pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

    # Detect the correct column for repo ID in the human table
    # It's usually 'repo_id' or 'repository_id'
    potential_keys = ['repo_id', 'repository_id', 'repo']
    left_key = next((k for k in potential_keys if k in pr_df.columns), None)

    if not left_key:
        print(f"Error: Could not find repo ID column. Available columns: {pr_df.columns.tolist()}")
        return

    print(f"Joining tables on PR.{left_key} and Repo.id...")
    merged_df = pd.merge(
        pr_df, 
        repo_df, 
        left_on=left_key, 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )

    # Filtering logic
    supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
    filtered_df = merged_df[
        (merged_df['stars'] > 100) &
        (merged_df['language'].isin(supported_langs))
    ].copy()

    # Normalize language names
    filtered_df['language'] = filtered_df['language'].str.lower()
    filtered_df.loc[filtered_df['language'] == 'typescript', 'language'] = 'javascript'

    # Sorting and Limiting
    filtered_df['created_at'] = pd.to_datetime(filtered_at_col) if (filtered_at_col := next((c for c in ['created_at', 'createdAt'] if c in filtered_df.columns), None)) else filtered_df.index
    filtered_df = filtered_df.sort_values(by=filtered_at_col, ascending=False)
    
    scan_list = filtered_df.head(500)[['full_name', 'number', 'title', 'language']].rename(columns={
        'full_name': 'repo_name',
        'language': 'primary_language'
    })
    
    scan_list['agent_name'] = 'human'
    scan_list.to_csv("human_scan_list.csv", index=False)
    print(f"Success: Created human_scan_list.csv with {len(scan_list)} entries.")

if __name__ == "__main__":
    extract_human_data()
