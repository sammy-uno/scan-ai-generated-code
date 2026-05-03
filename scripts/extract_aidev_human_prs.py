import pandas as pd

def extract_human_data():
    print("Streaming Human AIDev tables from Hugging Face...")
    # Load curated human PRs and Repository metadata
    pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/human_pull_request.parquet")
    repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")

    # Join on PR.repo_id to Repo.id
    merged_df = pd.merge(
        pr_df, 
        repo_df, 
        left_on='repo_id', 
        right_on='id', 
        how='inner', 
        suffixes=('_pr', '_repo')
    )

    # Filter by stars (>100) and supported languages
    supported_langs = ['Python', 'JavaScript', 'TypeScript', 'Java', 'Ruby']
    filtered_df = merged_df[
        (merged_df['stars'] > 100) &
        (merged_df['language'].isin(supported_langs))
    ].copy()

    # Normalize language names
    filtered_df['language'] = filtered_df['language'].str.lower()
    filtered_df.loc[filtered_df['language'] == 'typescript', 'language'] = 'javascript'

    # Sort by date and limit to 500
    filtered_df['created_at'] = pd.to_datetime(filtered_df['created_at'])
    filtered_df = filtered_df.sort_values(by='created_at', ascending=False)
    
    final_list = filtered_df.head(500)

    # Prepare final scan list
    scan_list = final_list[['full_name', 'number', 'title', 'language']].rename(columns={
        'full_name': 'repo_name',
        'language': 'primary_language'
    })
    
    scan_list.to_csv("human_scan_list.csv", index=False)
    print(f"Success: Created human_scan_list.csv with {len(scan_list)} newest entries.")

if __name__ == "__main__":
    extract_human_data()
