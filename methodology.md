# Chapter 3: Methodology

## 3.3 Large-Scale Automated Ingestion and Execution Framework
To empirically analyze the security profiles of real-world AI-generated code snippets collected within the AIDev framework, this study designed and implemented a production-grade, recursively chained static application security testing (SAST) framework using GitHub Actions. 

Autonomous AI agents often submit localized patches characterized by high-volume, low-density modifications, a pattern frequently tracked by established benchmarks like SWE-bench. Standard monolithic CI/CD workflows fail under these conditions due to strict runtime caps (e.g., GitHub's 6-hour job ceiling) and strict memory constraints when processing large repositories.

To bypass these system limitations, our architecture uses a **linear chunk-slicing and repository-dispatch model**. Rather than attempting to process thousands of repositories in a single run, the dataset is dynamically chunked into discrete processing queues managed by an automated pointer engine (`ai-scanner.py`). 

The system operates via five synchronized execution bounds:

The system operates via five synchronized execution bounds:

```text
[Discover Job] ──> [Analyze Matrix (Max 15)] ──> [Consolidate Report] 
       ▲                                                 │
       │───────── [Loop Dispatch Gateway] ───────────────┘
            (Fires Scan_Next_Chained_Batch if true)
```

1.  **Memory Hydration & Deduplication:** At startup, the workflow retrieves a persistent historical ledger (`master-database-accumulation`).
2.  **Parameterized Chunk Ingestion:** The framework processes data using a structured offset parameter (`CHUNK_OFFSET`). The discovery engine utilizes Pandas to select exactly 256 record rows from the global data queue, mapping them into an execution matrix.
3.  **Isolated Parallel Execution:** To optimize throughput, an `analyze` job spawns a parallel execution matrix (constrained to `max-parallel: 15`). Each isolated runner runs a targeted CodeQL query suite to analyze the target repository branch.
4.  **Consolidated Report Stream:** Upon matrix finalization, a reporting engine (`consolidate-report.py`) parses individual JSON outputs and appends them to the historical ledger. To prevent GitHub API timeouts and bypass the strict 1 Megabyte step summary limit, the script splits data tables into 50-row chunks, streaming them sequentially to the interface page.
5.  **Graduated Loop Transition:** Finally, a dedicated gateway evaluates data boundaries. If the index pointer is less than the total database size ($next\_offset < len(df)$), it triggers a repository dispatch payload (`Scan_Next_Chained_Batch`), launching the next batch run automatically.

## 3.4 Mitigating Differential Analysis Bias and Alert Noise
A major threat to validity in software mining research is **differential analysis bias**—the tendency of static analysis tools to flag legacy code smells or vulnerabilities on unchanged context lines. This study explicitly controls for this alert noise by evaluating only localized changes rather than scanning full source trees. 

By implementing an automated line-gate filter that maps code changes specifically to the lines touched in the pull request patch, this framework ensures that pre-existing technical debt is not incorrectly attributed to the AI agent.
