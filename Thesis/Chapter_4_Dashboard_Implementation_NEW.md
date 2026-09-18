# Chapter 4: Client-Side Analytical Dashboard Artifact Implementation

To ensure the final empirical findings are fully accessible, transparent, and interactive for evaluation, this study engineered a zero-backend, client-side dashboard interface layer (`index.html`). Because the data ingestion pipeline outputs completely structured, standardized JSON data arrays, the frontend application operates entirely within the user's web browser, removing the need for server-side processing runtimes or external database engine dependencies.

## 4.1 Central Routing Architecture and Gateway Interface
The primary entry point to the visualization system is established via a unified routing gateway interface (`index.html`). This centralized controller provides an intuitive, non-technical pathway for code reviewers and evaluation committees to navigate between the discrete evaluation tracks of the study.

As shown in **Figure 4.1**, the landing page uses a clean grid layout that separates the analytical views into distinct panels.

![Figure 4.1: Analytical Dashboard Routing Interface](dashboard_index_landing.png)
<p align="center"><em>Figure 4.1: Analytical Dashboard Routing Interface</em></p><br/>

Each navigation block features an explicit abstract detailing the underlying dataset parameters alongside a dedicated, color-coded call-to-action (CTA) trigger element to initialize the browser routing cycle:
*   **Symmetric Cross-Track Synthesis Card:** Anchored by a purple routing button, this option dynamically mounts the split-pane inter-cohort reporting dashboard to evaluate comparative patterns simultaneously.
*   **AI-Generated Evaluation Ledger Card:** Anchored by a blue routing button, this pathway initializes the asynchronous ingestion of the autonomous agent scanning database.
*   **Human Baseline Control Ledger Card:** Anchored by a green routing button, this option routes the browser to the empirical control dataset containing human contributor records.

## 4.2 AI Pull Request Evaluation Dashboard
The AI Pull Request Dashboard is dedicated entirely to rendering the scanning results of AI-authored PRs. Upon initialization, the client-side JavaScript engine executes asynchronous fetch routines to stream `accumulated_database.json` directly into local browser memory. This view isolates and maps the security profiles of the 1,000 AI-generated contributions, mounting the raw data array into interactive data tables built upon a structured column grid matching the user interface layout.

As visually documented in **Figure 4.2**, the dashboard workspace initializes an independent "Executive Summary" high-level metric container directly above the primary data grid.

![Figure 4.2: AI-Generated Pull Requests Consolidated Summary Report Interface](dashboard_ai_track.png)
<p align="center"><em>Figure 4.2: AI-Generated Pull Requests Consolidated Summary Report Interface</em></p><br/>

The ledger layout projects the raw data into thirteen user-facing column headers sorted in the exact sequential order displayed from left to right within the application interface:
1. **Security Alert Status:** Actionable link that handles detail row expansion toggle triggers.
2. **Repository Target** (`repo`): The target repository name path.
3. **Repository Stars** (`stars`): Proxy metric for project popularity and community adoption.
4. **PR Reference Link** (`link`): Clickable tracking number linking to the source code repository.
5. **Status** (`status`): The current development branch lifecycle resolution state (Open, Merged, Closed).
6. **AI Tool Engine** (`tool`): The generating autonomous agent name.
7. **Language** (`lang`): The target programming language profile scanned.
8. **LOC** (`loc`): The lines of code changed in the PR.
9. **CWE Discovered** (`cwes`): A sortable column displaying the unique CWEs discovered during the scan.
10. **Red Circle Badge:** Numerical summation integer for high-severity findings.
11. **Yellow Circle Badge:** Numerical summation integer for medium-severity findings.
12. **Blue Circle Badge:** Numerical summation integer for low-severity findings.
13. **Total Issues (Files):** Combined indicator displaying total vulnerability counts alongside modified file totals.

## 4.3 Human Pull Request Baseline Dashboard
Mirroring the structural design of the AI interface to maintain absolute empirical pairing, the Human Pull Request Baseline Dashboard executes independent asynchronous web routines targeting the `human_accumulated_database.json` data store. This view projects the behavioral profiles of the 1,000 human-authored control pull requests onto an identical user interface column layout.

As visually presented in **Figure 4.3**, the frontend layout maintains strict structural consistency by initializing an identical "Executive Summary" container directly above the human data ledger, exposing baseline balances (8 Vulnerable, 992 Clean).

![Figure 4.3: Human Pull Requests Consolidated Summary Report Interface](dashboard_human_track.png)
<p align="center"><em>Figure 4.3: Human Pull Requests Consolidated Summary Report Interface</em></p><br/>

The ledger layout incorporates the exact same thirteen sorting columns mapping from left to right, ensuring reviewers enjoy an identical functional feature set. For pull request rows that successfully cleared the line-filtering gate without triggering active security warnings, the system programmatically mounts a bright green "Clean Pass" badge inside the primary interaction column. Conversely, compromised rows receive the blue text "View Details" trigger link, providing identical access to expansion sub-tables and automated Defect Density computations to guarantee an completely unbiased visual comparison between evaluation tracks.

## 4.4 Inter-Cohort Comparative Reporting Dashboard
The comparative summary panel evaluates both `accumulated_database.json` and `human_accumulated_database.json` simultaneously to generate real-time, side-by-side comparison charts and metrics summaries. By activating the synthesis routine via this integrated view, the frontend application acts as a centralized macro-level reporting pane to cross-tabulate aggregate metrics—including volumetric lines changed, global merge rates, cumulative severity distributions, and alert dismissal thresholds—exposing overarching security divergence patterns across both evaluation tracks in a single consolidated interface.

As visually documented in **Figure 4.4**, the user interface implements a symmetric, dual-pane grid framework that locks the evaluation cohorts into parallel view containers.

![Figure 4.4: Inter-Cohort Side-by-Side Comparative Summary Interface](dashboard_global_summary.png)
<p align="center"><em>Figure 4.4: Inter-Cohort Side-by-Side Comparative Summary Interface</em></p><br/>

This centralized dashboard view parses both datasets on the client-side to generate instant vertical metrics stacks separated into four standardized diagnostic categories: General Size & Metrics, PR Lifecycle Status Distribution, Security Alert Breakdown, and Advanced Research Metrics (such as displaying the 52.5% vs 43.75% High-Severity Critical Ratio splits).
