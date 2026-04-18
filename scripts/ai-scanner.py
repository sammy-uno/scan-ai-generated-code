name: "PR-Only CodeQL Scan"

on:
  pull_request:
    # Triggers on PR creation or when new commits are pushed to the PR branch
    branches: [ main, master ]
    # Optional: ignore changes that don't need security scanning
    paths-ignore:
      - '**/*.md'
      - '**/*.txt'

jobs:
  analyze:
    name: Analyze Changed Code
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write # Required to upload alerts to the PR 'Checks' tab
      pull-requests: read

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          # Fetches all history so git diff can compare the PR to the base branch
          fetch-depth: 0 

      - name: Detect Languages with Changes
        id: detect
        run: |
          # Compare the current PR branch (HEAD) against the target branch (base_ref)
          git diff --name-only origin/${{ github.base_ref }}...HEAD > changed_files.txt
          
          DETECTED=""
          # Only add languages if their specific extensions appear in the diff
          grep -q "\.py$" changed_files.txt && DETECTED+="python,"
          grep -q "\.js$\|\.ts$\|\.jsx$\|\.tsx$" changed_files.txt && DETECTED+="javascript,"
          grep -q "\.java$\|\.kt$" changed_files.txt && DETECTED+="java,"
          grep -q "\.cs$" changed_files.txt && DETECTED+="csharp,"
          
          # Remove trailing comma and save to outputs
          FINAL_LANGS=$(echo ${DETECTED%?})
          echo "langs=$FINAL_LANGS" >> $GITHUB_OUTPUT
          echo "Found changed files for: $FINAL_LANGS"

      - name: Initialize CodeQL
        # Only initialize if at least one supported language was found in the diff
        if: steps.detect.outputs.langs != ''
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ steps.detect.outputs.langs }}
          # Incremental analysis reports only new alerts in the PR diff
          build-mode: none 

      - name: Perform CodeQL Analysis
        if: steps.detect.outputs.langs != ''
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ steps.detect.outputs.langs }}"
