import pandas as pd
import sys

def extract_human_data():
    print("Streaming Human AIDev tables from Hugging Face...")
    try:
        pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/human_pull_request.parquet")
        repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

        # FIX: The repository table uses 'url', while the human_pr table uses 'repo_url'
        # Let's verify and join
        left_key = 'repo_url'
        right_key = 'url' 

        if left_key not in pr_df.columns or right_key not in repo_df.columns:
            print(f"Column mismatch!")
            print(f"PR Columns: {pr_df.columns.tolist()}")
            print(f"Repo Columns: {repo_df.columns.tolist()}")
            sys.exit(1)

        print(f"Joining tables on PR.{left_key} and Repo.{right_key}...")
        merged_df = pd.merge(
            pr_df, 
            repo_df, 
            left_on=left_key, 
            right_on=right_key, 
            how='inner', 
            suffixes=('_pr', '_repo')
        )

        if merged_df.empty:
            print("Error: Merge resulted in empty dataset. The URLs in both tables might not match format.")
            sys.exit(1)

        # Filter criteria
        supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
        filtered_df = merged_df[
            (merged_df['stars'] > 100) &
            (merged_df['language'].isin(supported_langs))
        ].copy()

        # Normalize language
        filtered_df['language'] = filtered_df['language'].str.lower()
        filtered_df.loc[filtered_df['language'] == 'typescript', 'language'] = 'javascript'

        # Sort and Limit
        filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
        filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
        
        # 'full_name' is usually the repo name (e.g., 'owner/repo')
        scan_list = filtered_df.head(500)[['full_name', 'number', 'title', 'language']].rename(columns={
            'full_name': 'repo_name',
            'language': 'primary_language'
        })
        
        scan_list['agent_name'] = 'human'
        scan_list.to_csv("human_scan_list.csv", index=False)
        print(f"Success: Created human_scan_list.csv with {len(scan_list)} entries.")

    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1)

if __name__ == "__main__":
    extract_human_data()
