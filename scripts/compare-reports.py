import os
import glob

def main():
    print("==========================================")
    print("🖥️ RAW FILESYSTEM INSPECTION LOG")
    print("==========================================")
    print(f"Current Directory: {os.getcwd()}")
    print(f"Folder 'all-results' exists: {os.path.exists('all-results')}")
    
    if os.path.exists('all-results'):
        print(f"Flat folder contents: {os.listdir('all-results')}")
        
        # Scan recursively to see EXACTLY where the files are hiding
        recursive_files = glob.glob('all-results/**/*', recursive=True)
        print(f"Total objects found recursively: {len(recursive_files)}")
        for f in recursive_files:
            print(f" -> FOUND ON DISK: {f}")
            
    print("==========================================")
    
    # Write a placeholder summary so the workflow completes gracefully
    with open('summary.md', 'w') as out:
        out.write("# 🔍 Diagnostic Report\nCheck the raw console logs to see what files were found on disk.")
        
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    if os.path.exists('summary.md'):
        with open(summary_file, 'w') as out, open('summary.md', 'r') as src:
            out.write(src.read())

if __name__ == "__main__":
    main()
