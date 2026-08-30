# 3.3 Large-Scale Automated Ingestion and Execution Framework

To empirically analyze the security profiles of AI-generated and human-authored code snippets within the AIDev framework, this study engineered a static application security testing (SAST) execution pipeline built on GitHub Actions.

The implementation of a linear chunk-slicing and repository-dispatch model was strictly required due to specific platform engineering constraints. First, GitHub Actions imposes a rigid workflow concurrency ceiling that restricts a dynamic build matrix to a maximum of 256 parallel execution jobs per run. Attempting to scan a monolithic selection of 1,000 pull requests (PRs) simultaneously causes immediate deployment failures. Second, the platform enforces a strict 6-hour runtime execution cap per individual job. High-throughput security tools like CodeQL exceed these boundaries when executing thousands of deep semantic scans sequentially on a single runner.

To ensure high reproducibility and eliminate operational overhead, the pipeline was explicitly architected to operate on standard Linux (2-core) GitHub-hosted runners, which are natively provided under GitHub's free tier and offer unlimited compute minutes for open-source public repositories.

To operate within the platform constraints of these standard free-tier runners, the pipeline applies a nested throttling mechanism that optimizes parallel throughput across an inner and outer loop structure:

1. **The Outer Loop (Batching Step):** The pipeline splits the 1,000 targeted pull requests per track into four sequential batches of 250. The AI-generated and human-authored tracks operate independently, each managed by its own GitHub Actions workflow executing a dedicated orchestration script: `ai-scanner.py` for the AI evaluation track and `human-scanner.py` for the human baseline track.
2. **The Inner Loop (Parallel Matrix Sub-throttling):** Within each 250-PR batch run, the framework dynamically fans out execution across an automated sub-matrix. To prevent API rate drops, runner saturation, and account-wide resource throttling, the pipeline enforces a strict horizontal ceiling that restricts active processing to 10 parallel pull request scans (`max-parallel: 10`) concurrently inside the active runner block.

The execution loop operates across five precise stages:

```
[Discover Job (250 PRs)] ──> [Analyze Matrix (Max 10 Parallel)] ──> [Consolidate Report] 
           ▲                                                               │
           │─────────────────── [Loop Dispatch Gateway] ───────────────────┘
                   (Dispatches Scan_Next_Chained_Batch if index < 1000)
```

1. **Restore Accumulated Scanning Database:** The workflow initial step retrieves the historical scanning records from the tracking repository. A centralized JSON database is engineered into the architecture to preserve state across ephemeral GitHub Actions runner instances. By restoring this file at the start of each run, the pipeline maintains data continuity and ensures reliable evaluation across all four macro-batches.
2. **Parameterized Chunk Ingestion:** The runtime environment reads a standardized `CHUNK_OFFSET` parameter. The discovery engine uses the Python Pandas library to isolate exactly 250 rows from the primary dataset queue matching that offset.
3. **Isolated Parallel Execution:** The platform spawns the inner execution matrix, fanning out the active batch to process 10 PR scans in parallel concurrently on independent standard free-tier virtual machines. Each individual runner initiates an independent CodeQL query suite targeted exclusively at the localized patch lines of the designated repository branch.
4. **Consolidated Report Stream:** Upon the completion of the 250 parallel matrixed scans, an orchestration script (`consolidate-report.py`) parses the individual scanning outputs. It leverages the CodeQL Static Analysis Results Interchange Format (SARIF) files to compile and display the "Consolidated Final Report Summary" for the executed batch.
5. **Graduated Loop Transition:** A gateway evaluates the current index pointer against the data boundary. If the processed offset is less than the 1,000 PR requirement (`index < 1000`), the workflow fires a repository dispatch payload (`Scan_Next_Chained_Batch`), triggering the next loop automatically. This condition allows exactly four sequential iterations (offsets 0, 250, 500, and 750) to run, cleanly halting the execution loop once the cumulative 1,000 PR dataset baseline is fully extracted.
