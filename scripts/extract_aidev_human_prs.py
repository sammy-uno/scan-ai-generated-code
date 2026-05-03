import pandas as pd
import sys

def extract_human_data():
    print("Streaming Human AIDev tables from Hugging Face...")
    try:
        pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/human_pull_request.parquet")
        repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

        # JOIN LOGIC: Use repo_url from PRs and html_url from Repos
        print("Joining tables on PR.repo_url and Repo.html_url...")
        merged_df = pd.merge(
            pr_df, 
            repo_df, 
            left_on='repo_url', 
            right_on='html_url', 
            how='inner', 
            suffixes=('_pr', '_repo')
        )

        if merged_df.empty:
            print("Error: Merge resulted in empty dataset. Check if URLs match.")
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
        
        scan_list = filtered_df.head(500)[['full_name', 'number', 'title', 'language']].rename(columns={
            'full_name': 'repo_name',
            'language': 'primary_language'
        })
        
        scan_list['agent_name'] = 'human'
        scan_list.to_csv("human_scan_list.csv", index=False)
        print(f"Success: Created human_scan_list.csv with {len(scan_list)} entries.")

    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1) # This forces the GitHub Action to show a red "Fail" icon

if __name__ == "__main__":
    extract_human_data()
