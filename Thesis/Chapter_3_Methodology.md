# Chapter 3: Methodology

## 3.1 Distributed Cloud Orchestration Architecture
To execute large-scale semantic security analysis across two distinct authorship cohorts while operating under modern DevOps platform constraints, this study engineered a distributed static application security testing (SAST) execution pipeline built on **GitHub Actions virtualized infrastructures**. The architecture is designed to enforce absolute experimental isolation, routing the AI-agent track and the human developer track into entirely separate, asynchronous execution loops orchestrated by `ai-scanner.py` and `human-scanner.py` respectively. 

The technical design of this framework was explicitly dictated by two platform engineering constraints enforced by the cloud runner environment:
* **The Matrix Capacity Ceiling:** The platform imposes a strict, hard concurrency limit of **256 parallel execution jobs** per individual workflow instantiation. Attempting to evaluate a monolithic dataset of 1,000 pull requests simultaneously results in immediate platform deployment failures.
* **The Execution Timeout Constraint:** Individual compute jobs are bound by a rigid **6-hour execution cap**. Deep semantic compilers and graph-parsing static analysis suites routinely exceed this boundary when forced to execute thousands of repository evaluations sequentially on a single runner.

To operate deterministically within these boundaries without generating financial overhead, the ingestion engine implements a **nested dual-loop throttling model** executing on standard 2-core Linux virtual machines. The operational mechanics of this orchestration layer are divided into two distinct components:

1. **The Outer Loop (Linear Chunk Ingestion):** The primary 1,000-PR dataset queue per track is programmatically partitioned into four uniform, sequential chunks of **250 pull requests**. Each chunk execution passes an explicit `CHUNK_OFFSET` environment variable to isolate rows via the Python Pandas library. State persistence across these ephemeral compute barriers is maintained by an atomic read-append-write loop that hydrates a persistent JSON data layer.
2. **The Inner Loop (Parallel Matrix Sub-Throttling):** Within an active chunk, execution fans out across a dynamic horizontal build matrix. To prevent platform API rate limits, out-of-memory runner crashes, and account-wide resource throttling, the pipeline enforces a localized concurrency block configured strictly to a maximum ceiling of 10 parallel jobs (`max-parallel: 10`).

## 3.2 Persistent State Aggregation Framework
Because cloud-hosted runners operate in ephemeral virtual environments that completely discard local state upon job finalization, a persistent tracking layer was required to aggregate empirical telemetry across decoupled batch iterations. This study implemented a dual database architecture, establishing two separate JSON data stores—`accumulated_database.json` for the AI engine cohort and `human_accumulated_database.json` for the human baseline group—to eliminate cross-track metadata pollution.

The storage schema utilizes a deeply nested object mapping pattern. To demonstrate the structural properties of this telemetry layer, the formal JSON schema is validated below against an authentic vulnerable payload pulled during the evaluation of repository `webgptorg/promptbook` on Pull Request `#276`:

```json
{
    "repo": "webgptorg/promptbook",
    "link": "[#276](https://github.com)",
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
            "cwes": ["CWE-134"]
        },
        {
            "vulnerability": "js/missing-rate-limiting",
            "severity_label": "🔴 High",
            "file_line": "src/remote-server/startRemoteServer.ts#L435",
            "description": "This route handler performs [authorization](1), but is not rate-limited.",
            "cwes": ["CWE-307", "CWE-400", "CWE-770"]
        }
    ],
    "stars": 121
}
```

The data fields within this accumulative tracking layer are programmatically computed using a strict operational specification:
* **`loc` (Lines of Code):** Computed strictly as the net integer of added or edited lines within the pull request patch that pass the coordinate gate.
* **`issues_files`:** A composite tracking string mapping the absolute count of verified vulnerabilities directly against the total number of files changed in the PR, formatted as `total_vulnerabilities (total_files_changed)`.
* **`density` (Defect Density):** A normalized metric computed via the following formula:
$$\text{Defect Density} = \frac{\text{Total Alerts } (h + m + l)}{\text{Lines of Code } (loc)}$$

## 3.3 Incremental CodeQL Dataflow Graph Taint Tracking
To isolate the security profiles of incoming pull request modifications without capturing pre-existing project repository technical debt, the methodology implements an **incremental, diff-informed semantic analysis engine**. Monolithic SAST evaluations generate substantial statistical noise by capturing bugs residing on lines completely unmodified by the active author. This study completely mitigates this variable by developing an automated line-gate filtering engine that pairs Abstract Syntax Tree (AST) dataflow tracks with localized Git delta parameters.

### 3.3.1 Local Checkout and Workspace Assessment
The runner reads the active patch metadata (`pr_num`, `repo`), establishes an isolated workspace branch, and pulls the target contribution locally via the Git reference interface:
```bash
git fetch origin pull/{pr_num}/head:pr_{pr_num}
```
To ensure that the compiled file tree executes cleanly against contemporary dependencies, the runner checks out the target branch and performs an automated merge assessment against the target repository reference branch (`git checkout pr_{pr_num} && git rebase origin/main`).

### 3.3.2 Monolithic Compilation and AST Mapping
The framework triggers the CodeQL compiler package using the `build-mode: none` extraction standard for interpreted environments. The compiler maps the comprehensive repository structural architecture into an uncompiled source dictionary zip file (`src.zip`), parsing variable scopes, operational code blocks, and package dependencies into a localized relational database.

### 3.3.3 Graph Taint-Analysis Execution
The engine executes security-extended QL query packs to evaluate systemic data flows across the AST graph nodes, mapping data vulnerabilities via explicit tracking paths:
$$\text{Dataflow Path} = \text{Source}_{\text{untrusted}} \longrightarrow \text{Sanitizer}_{\text{omitted}} \longrightarrow \text{Sink}_{\text{vulnerable}}$$
The analysis explicitly traces whether untrusted inputs flow directly into dangerous operational endpoints without traversing a validated cleansing algorithm.

### 3.3.4 Coordinate-Level Git Diff Range Filtering
To isolate authorship failures, the report compiler intercepts the global tool-specific vulnerabilities log and maps it against raw Git diff range coordinates. The script executes an underlying Git hunk parsing loop against the common branch ancestor:
```bash
git diff origin/main...HEAD --unified=0
```
This outputs every modified code hunk, capturing the file path and the exact line coordinates for the changed blocks to establish a localized tracking array:
$$\text{Diff Range Bucket} = \{ \text{File Path}, \; [\text{Line}_{\text{start}}, \; \text{Line}_{\text{end}}] \}$$

The framework completes report generation by running a coordinate cross-tabulation filter on every individual CodeQL Static Analysis Results Interchange Format (SARIF) alert:
$$\text{Alert Validated} = \begin{cases} \text{if } (\text{Alert}_{\text{file}} = \text{Diff}_{\text{file}}) \ \wedge \ (\text{Alert}_{\text{line}} \in [\text{Line}_{\text{start}}, \, \text{Line}_{\text{end}}]) & \implies \text{True} \\ \text{otherwise} & \implies \text{False} \end{cases}$$
If an alert's line intersects directly with the git patch coordinates, it is saved as an authentic defect. If it flags an unchanged line outside the PR hunk boundaries, it is dropped as legacy debt, ensuring total empirical isolation.
