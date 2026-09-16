# Chapter 4: Client-Side Analytical Dashboard Artifact Implementation

To ensure the final empirical findings are fully accessible, transparent, and interactive for evaluation, this study engineered a zero-backend, client-side dashboard interface layer (`index.html`) [source: 1]. Because the data ingestion pipeline outputs completely structured, standardized JSON data arrays, the frontend application operates entirely within the user's web browser, removing the need for server-side processing runtimes or external database engine dependencies [source: 1]. The architecture reads the extracted telemetry files dynamically to populate three focused operational views [source: 1]:

```
                      ┌──> [4.1 AI PRs Dashboard] ───────> (Reads accumulated_database.json)
                      │
[index.html Frontend] ├──> [4.2 Human PRs Dashboard] ────> (Reads human_accumulated_database.json)
                      │
                      └──> [4.3 Comparative Dashboard] ──> (Cross-tabulates both datasets)
```

## 4.1 AI Pull Request Evaluation Dashboard
The AI Pull Request Dashboard is dedicated entirely to rendering the scanning results of AI-authored PRs [source: 1]. Upon initialization, the client-side JavaScript engine executes asynchronous fetch routines to stream `accumulated_database.json` directly into local browser memory [source: 1]. This view isolates and maps the security profiles of the 1,000 AI-generated contributions, mounting the raw data array into interactive data tables built upon a structured column grid matching the user interface layout [source: 1].

The dashboard interface projects the raw data into user-facing column headers sorted in the exact sequential order displayed from left to right within the application interface [source: 1]:
1. **Repository** (`repo`): The target repository name path [source: 1].
2. **Stars** (`stars`): The target repository star count, serving as a proxy metric for project popularity and community adoption [source: 1].
3. **Pull Request Link** (`link`): The clickable tracking number and source code URL indicator [source: 1].
4. **Status** (`status`): The current development branch lifecycle resolution state [source: 1].
5. **Tool Used** (`tool`): The generating autonomous agent name [source: 1].
6. **Language** (`lang`): The target programming language profile scanned [source: 1].
7. **LOC** (`loc`): The lines of code changed in the PR [source: 1].
8. **CWE Discovered** (`cwes`): A sortable column displaying the unique CWEs discovered during the scan [source: 1].
9. **High** (`h`): Numerical summation integer for high-severity findings [source: 1].
10. **Medium** (`m`): Numerical summation integer for medium-severity findings [source: 1].
11. **Low** (`l`) : Numerical summation integer for low-severity findings [source: 1].
12. **Total issues (Files)** (`issues_files`): The total count of defects and overall files modified [source: 1].

To facilitate manual defect reviews without table clutter, any pull request containing active vulnerabilities displays a custom "View Details" contextual link [source: 1]. When activated, this link maps the target row to an independent display panel that parses the underlying `findings_details` array, exposing the localized vulnerability ID, severity label, precise file path with line numbers (`file_line`), and structural description, while programmatically outputting the normalized Defect Density score directly above the sub-table component [source: 1].

## 4.2 Human Pull Request Baseline Dashboard
Mirroring the structural design of the AI interface to maintain absolute empirical pairing, the Human Pull Request Baseline Dashboard executes independent asynchronous web routines targeting the `human_accumulated_database.json` data store [source: 1]. This view projects the behavioral profiles of the 1,000 human-authored control pull requests onto an identical user interface column layout [source: 1]. It provides reviewers with an identical functional feature set, incorporating the same "View Details" expansion sub-tables and programmatic Defect Density computations to ensure an unbiased visual comparison between evaluation tracks [source: 1].

## 4.3 Inter-Cohort Comparative Reporting Dashboard
The comparative summary panel evaluates both `accumulated_database.json` and `human_accumulated_database.json` simultaneously to generate real-time, side-by-side comparison charts and metrics summaries [source: 1, 3]. By activating the synthesis routine via this integrated view, the frontend application acts as a centralized macro-level reporting pane to cross-tabulate aggregate metrics—including volumetric lines changed, global merge rates, cumulative severity distributions, and alert dismissal thresholds—exposing overarching security divergence patterns across both evaluation tracks in a single consolidated interface [source: 1].