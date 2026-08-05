  discover:
    name: Find AI PRs
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.detect.outputs.matrix_data }}
    steps:
      - uses: actions/checkout@v5
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      # 🚀 THE CROSS-BATCH PROTECTION BRIDGE: 
      # Fetch the master json file from prior runs so the discover job knows what was already scanned!
      - name: Fetch Historical Database Snapshot for Deduplication
        env:
          GH_TOKEN: ${{ secrets.GLOBAL_SCAN_PAT }}
        run: |
          echo "📥 Downloading master database to hydrate scanner deduplication memory..."
          gh run download --name "master-database-accumulation" --dir "all-results" || true

      - name: Discover Scan Matrix
        id: detect
        env:
          GH_TOKEN: ${{ secrets.GLOBAL_SCAN_PAT }}
          CHUNK_OFFSET: ${{ github.event.inputs.offset || github.event.client_payload.offset || '0' }}
        run: |
          pip install pandas
          python scripts/ai-scanner.py
