# 2.0 Automated Security Scanning and Telemetry Extraction Methodology

## 2.1 Large-Scale Automated Ingestion and Execution Framework

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


## 2.2 Persistent Accumulative JSON State-Database Architecture

### Data Persistence Layer
Because GitHub Actions runners operate in ephemeral environments that discard local state upon job completion, a dedicated persistence layer was engineered to aggregate metrics across decoupled batch runs. To prevent cross-contamination and maintain strict experimental separation across the distinct GitHub Actions workflow tracks (AI versus Human PR scanning), telemetry is routed into two separate databases: `accumulated_database.json` captures evaluation records for the AI-generated PR cohort, whereas `human_accumulated_database.json` maintains the baseline data for the human control group.

The pipeline maintains continuity across all four 250-PR batch executions by operating a strict read-append-write loop. At the start of a batch run, the script hydrates its memory by reading the existing JSON file. As the parallel runners complete their scans, their parsed metrics are appended to the dataset array. Once a batch completes, the memory tree is serialized atomically back to disk.

Every pull request record within these finalized databases adheres to a rigid JSON object structure. The structural blueprint of an ingested pull request record containing verified vulnerabilities is formally specified below, utilizing an extraction of the real-world sample repository pull request [webgptorg/promptbook/pull/276](https://github.com/webgptorg/promptbook/pull/276) as an explicit case example of a scanned JSON PR payload:

```json
{
    "repo": "webgptorg/promptbook",
    "link": "[#276](https://github.com/webgptorg/promptbook/pull/276)",
    "tool": "Copilot",
    "lang": "javascript",
    "loc": 549,
    "cwes": "CWE-134, CWE-307, CWE-400, CWE-770",
    "h": 1,
    "m": 2,
    "l": 0,
    "issues_files": "3 (7)",
    "density": 0.0055,
    "status": "🟣 Merged",
    "has_issues_bool": true,
    "pr_num": "276",
    "findings_details": [
        {
            "vulnerability": "js/tainted-format-string",
            "severity_label": "🟡 Medium",
            "file_line": "src/remote-server/startRemoteServer.ts#L427",
            "description": "Format string depends on a [user-provided value](1).",
            "cwes": [
                "CWE-134"
            ]
        },
        {
            "vulnerability": "js/tainted-format-string",
            "severity_label": "🟡 Medium",
            "file_line": "src/remote-server/startRemoteServer.ts#L512",
            "description": "Format string depends on a [user-provided value](1).",
            "cwes": [
                "CWE-134"
            ]
        },
        {
            "vulnerability": "js/missing-rate-limiting",
            "severity_label": "🔴 High",
            "file_line": "src/remote-server/startRemoteServer.ts#L435",
            "description": "This route handler performs [authorization](1), but is not rate-limited.",
            "cwes": [
                "CWE-307",
                "CWE-400",
                "CWE-770"
            ]
        }
    ],
    "stars": 121
}
```

### Data Field Metrics Specification
The data fields inside the accumulative JSON database are strictly computed as follows:

*   **`repo` / `pr_num` / `link`**: Explicit tracking strings mapping the upstream target repository, the pull request tracker index, and its markdown URL link.
*   **`tool`**: Identifies the generating agent for the AI track (e.g., `Copilot`), or registers human authorship within the human baseline group.
*   **`lang`**: The programming language profile of the target patch evaluated by the CodeQL language analysis pack (e.g., `javascript`).
*   **`loc`**: The net lines of code altered within the pull request patch that successfully passed the line-gate filtering engine.
*   **`cwes`**: A top-level aggregated summary string of all unique Common Weakness Enumeration identifiers flagged within the pull request boundary.
*   **`h` / `m` / `l`**: Strict integers recording the count of verified High (`h`), Medium (`m`), and Low (`l`) severity vulnerabilities found in the patch.
*   **`issues_files`**: A formatted summary string capturing the total count of verified vulnerabilities alongside the total number of files changed in the pull request in parentheses—represented as `total_vulnerabilities (total_files_changed in the PR)`.
*   **`density`**: The normalized defect density value, calculated directly as:
    $$\text{Defect Density} = \frac{\text{Total Alerts (h + m + l)}}{\text{Lines of Code (loc)}}$$
*   **`status`**: The current lifecycle resolution branch of the target pull request (e.g., `🟢 Open`, `🟣 Merged`, `🔴 Closed`).
*   **`has_issues_bool`**: A binary boolean flag (`true`/`false`) establishing whether the pull request contains one or more security findings.
*   **`findings_details`**: An inner array mapping the explicit tool-specific vulnerability ID (`vulnerability`), severity level (`severity_label`), its precise file tree location and line number (`file_line`), the context description (`description`), and a localized array of corresponding CWE markers (`cwes`).
*   **`stars`**: An integer record of the target repository's GitHub star telemetry at the time of ingest, serving as a proxy metric for project popularity.


## 2.3 Incremental CodeQL Semantic Analysis and Diff Line Filtering Logic

To accurately contrast the code safety profiles of the two evaluation tracks without capturing pre-existing project repository technical debt, the pipeline implements an incremental, diff-informed code analysis engine. Standard static application security testing (SAST) tools typically scan an entire codebase monolithically, which introduces significant statistical noise when evaluating isolated pull request changes. To eliminate these variables, this framework utilizes the CodeQL Command Line Interface (CLI) bundle configured to run in an active line-gate tracking layer, mapping alerts exclusively to modified lines of code.

The orchestration pipeline handles source ingestion, database compilation, and target patch filtering through an automated four-stage sequence:

```
                  ┌──────────────────────────────────────────────┐
                  │ 1. Git Reference Fetching and Local Checkout │
                  └──────────────────────┬───────────────────────┘
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ 2. Monolithic CodeQL Database Extraction     │
                  └──────────────────────┬───────────────────────┘
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ 3. AST Semantic Graph Taint Tracking Queries │
                  └──────────────────────┬───────────────────────┘
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ 4. Git Diff Range Mapping and Line Filtering │
                  └──────────────────────────────────────────────┘
```

### 2.3.1 Git Reference Fetching and Local Checkout
When an orchestration script (`ai-scanner.py` or `human-scanner.py`) processes an active row from the primary queue, it extracts the pull request identifier tracking token (`pr_num`) and repository origin path (`repo`). The virtual environment initializes an isolated branch workspace by executing downstream Git commands:
1.  **Remote Baseline Identification:** The runner establishes a connection to the upstream repository and executes `git fetch origin pull/{pr_num}/head:pr_{pr_num}` to map the isolated target contribution branch locally.
2.  **Target Integration Rebase:** To verify that the compiled file tree executes cleanly against contemporary staging dependencies, the runner checks out the branch and performs an automated merge assessment against the default main branch reference (`git checkout pr_{pr_num} && git rebase origin/main`).

### 2.3.2 Monolithic Database Extraction and AST Resolution
Once the workspace branch is normalized, the system triggers the CodeQL compiler framework using the `build-mode: none` extraction pack for interpreted scripts. CodeQL cannot perform reliable semantic analysis if it is restricted strictly to raw patch files because the engine requires structural visibility into surrounding components to resolve external declarations, functional dependencies, and imported modules.

The pipeline handles database extraction across a dual-stage execution layer:
*   **Database Initializer:** The pipeline initializes the code capture environment by executing:
    ```bash
    codeql database create ./db --language=javascript --source-root=./src
    ```
*   **AST Tree Generation:** The extractor maps the entire repository file architecture into an uncompiled source directory zip (`src.zip`), resolving variable scoping, function structures, and conditional blocks into relational Abstract Syntax Tree (AST) definitions.

### 2.3.3 Semantic Graph Taint Tracking Queries
With the structural relational database hydrated, the engine runs the security-extended CodeQL analysis query suite. Rather than executing simple regex pattern matching, the engine runs structural queries written in object-oriented QL to trace data flow graphs across the AST nodes.

The engine maps security violations by computing explicit taint tracking paths:

$$\text{Dataflow Connection} = \text{Source}_{\text{untrusted}} \longrightarrow \text{Sanitizer}_{\text{omitted}} \longrightarrow \text{Sink}_{\text{vulnerable}}$$


The queries identify paths where untrusted, user-controlled inputs (`Source`) navigate through execution routines without safety checks (`Sanitizer`) to trigger dangerous functions (`Sink`), such as passing raw environment data directly into an uncontrolled absolute system shell path.

### 2.3.4 Git Diff Range Mapping and Line Filtering
The core filtering mechanism runs during the final report compilation phase, converting global alerts into isolated pull request metrics. Left unconstrained, the taint-tracking execution engine outputs all security alerts found anywhere in the host project's repository history. To ensure strict empirical isolation, the script extracts the file additions and line modifications introduced exclusively by that specific pull request patch.

The orchestration framework handles this filtering through a multi-tiered validation function:
1.  **Extract Patch Range Coordinates:** The script runs an underlying Git diff processing loop against the common branch ancestor:
    ```bash
    git diff origin/main...HEAD --unified=0
    ```
    This outputs every modified hunk, isolating the target file path and the exact starting and ending line index coordinates for added or edited blocks:
  
$$\text{Diff Range Bucket} = \{ \text{File Path} \, [\text{Line}_{\text{start}} \, \text{Line}_{\text{end}}] \}$$
    
2.  **SARIF Location Cross-Tabulation:** The script invokes the CodeQL reporting parser, specifying the output formatting as a Static Analysis Results Interchange Format (SARIF) schema file. The script then executes a strict coordinate cross-matching loop: 

$$\text{Alert Validated} = \begin{cases} \text{if } (\text{Alert}_{\text{file}} = \text{Diff}_{\text{file}}) \ \wedge \ (\text{Alert}_{\text{line}} \in [\text{Line}_{\text{start}}, \, \text{Line}_{\text{end}}]) & \implies \text{True} \\ \text{otherwise} & \implies \text{False} \end{cases}$$

3.  **Metrics Array Serialization:** If a vulnerability's file track location matches an entry in the diff range bucket, the alert is classified as an authentic authorship failure and appended to the tracking array. If the vulnerability is found on an unchanged line outside the pull request patch boundaries, the line filtering gate drops the alert entirely. This ensures that pre-existing repository flaws do not contaminate the empirical tracking results of the evaluation cohorts.
