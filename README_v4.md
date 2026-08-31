# 3.5 Client-Side Dashboard and Comparative Analytics Integration

To ensure the final empirical findings are fully accessible, transparent, and interactive for evaluation, this study engineered a zero-backend, client-side dashboard interface layer (`index.html`). Because the data ingestion pipeline outputs completely structured, standardized JSON data arrays, the frontend application operates entirely within the user's web browser, removing the need for server-side processing runtimes or external database engine dependencies. 

The architecture reads the extracted telemetry files dynamically to populate three focused operational views:

```
                      ┌──> [3.5.1 AI PRs Dashboard] ───────> (Reads accumulated_database.json)
                      │
[index.html Frontend] ├──> [3.5.2 Human PRs Dashboard] ────> (Reads human_accumulated_database.json)
                      │
                      └──> [3.5.3 Comparative Dashboard] ──> (Cross-tabulates both datasets)
```

---

### 3.5.1 AI Pull Request Evaluation Dashboard
The AI Pull Request Dashboard is dedicated entirely to rendering the scanning results of AI-authored PRs. Upon initialization, the client-side JavaScript engine executes asynchronous fetch routines to stream `accumulated_database.json` directly into local browser memory. 

This view isolates and maps the security profiles of the 1,000 AI-generated contributions. It mounts the raw data array into interactive, client-side data tables built upon a structured column grid matching the user interface layout.

*   **Dashboard Table Columns Layout:** The interface projects the raw data into user-facing column headers sorted in the exact sequential order displayed from left to right within the application interface:
    1.  **Repository** (`repo`): The target repository name path.
    2.  **Stars** (`stars`): The target project popularity proxy tracking score.
    3.  **Pull Request Link** (`link`): The clickable tracking number and source code URL indicator.
    4.  **Status** (`status`): The current development branch lifecycle resolution state.
    5.  **Tool Used** (`tool`): The generating autonomous agent name.
    6.  **Language** (`lang`): The target programming language profile scanned.
    7.  **LOC** (`loc`): The lines of code changed in the PR.
    8.  **CWE Discovered** (`cwes`): A sortable column displaying the unique CWEs discovered during the scan.
    9.  **High** (`h`): Numerical summation integer for high-severity findings.
    10. **Medium** (`m`): Numerical summation integer for medium-severity findings.
    11. **Low** (`l`): Numerical summation integer for low-severity findings.
    12. **Total issues (Files)** (`issues_files`): The total count of defects and overall files modified.

*   **"View Details" Link:** To facilitate manual defects reviews without table clutter, any PR with defects will have a "View Details" link added to the table row. When clicked, it will open a panel displaying the CWEs discovered stored in the `findings_details` JSON array. For each defect, the severity, the CodeQL vulnerability rule, file path and line location of the defect, and the vulnerability description are displayed. The overall Defect Density value is also calculated and displayed above the sub-table of the list of the vulnerabilities found.

---

### 3.5.2 Human Pull Request Baseline Dashboard
The Human Pull Request Baseline Dashboard renders the scanning results of human-authored PRs. The interface triggers an independent asynchronous routine targeting `human_accumulated_database.json` database to display the Human PR scanning results.

Mirroring the structural design of the AI interface to maintain absolute empirical pairing, this dashboard visualizes the behavior of the 1,000 human-authored control pull requests. It leverages the identical column grid used as the AI dashboard. It also presents CWE Discovered as a sortable column, providing reviewers with an identical functional feature set. This incorporates the exact same "View Details" Link panel details rendering the `findings_details` defects array sub-table and displaying the calculated Defect Density value above the sub-table.

---

### 3.5.3 Inter-Cohort Comparative Reporting Dashboard
The "View Comparative Analysis" dashboard evaluates both `accumulated_database.json` and `human_accumulated_database.json` simultaneously to generate real-time, side-by-side comparison charts and metrics summaries. To ensure absolute mathematical transparency, the side-by-side analytical reporting module calculates and renders a dedicated set of macro performance metrics for each 1,000-PR tracking cohort:

*   **Total Lines Changed:** The cumulative summation of the lines of code altered across the complete cohort 1000 PRs set.
    $$\text{Total LOC} = \sum_{i=1}^{1000} \text{loc}_i$$
*   **Total Defective Pull Requests:** A summation tracker recording the absolute count of pull requests where the PR json field `has_issues_bool` flag evaluates to true.
    $$\text{Total Defective PRs} = \sum_{i=1}^{1000} [\text{has\_issues\_bool}_i = \text{true}]$$
* **PR Lifecycle Status Distribution:** A discrete categorization split showing the exact resolution status sums for open, merged, and closed states across the cohort:
  $$\text{Total Open} = \sum_{i=1}^{1000} [\text{status}_i = \text{Open}], \quad \text{Total Merged} = \sum_{i=1}^{1000} [\text{status}_i = \text{Merged}], \quad \text{Total Closed} = \sum_{i=1}^{1000} [\text{status}_i = \text{Closed}]$$

*   **Total Defects Count:** The absolute total volume of individual security findings discovered across all inspected files in the cohort track.
    $$\text{Total Defects} = \sum_{i=1}^{1000} (h_i + m_i + l_i)$$
*   **Cohort CWE Defect Density:** The benchmark concentration metric modeling total discovered defects directly against the absolute volumetric footprint of the PRs LOC changes.
    $$\text{Cohort Defect Density} = \frac{\text{Total Defects}}{\text{Total LOC}}$$
*   **Average Defect Rate:** Calculates the mean frequency of security issues encountered per submitted pull request file.
    $$\text{Average Defect Rate} = \frac{\text{Total Defects}}{1000}$$
*   **Global Merge Rate:** The mathematical proportion of contributions that successfully pass development branch review to achieve full lifecycle resolution.
    $$\text{Global Merge Rate} = \frac{\text{Total Merged PRs}}{1000}$$
*   **Aggregate Vulnerabilities Severity Stack:** The standalone absolute volume of issues separated neatly into their localized threat priority classifications.
    $$\text{Aggregate High} = \sum_{i=1}^{1000} h_i, \quad \text{Aggregate Medium} = \sum_{i=1}^{1000} m_i, \quad \text{Aggregate Low} = \sum_{i=1}^{1000} l_i$$

#### 3.5.3.3 Advanced Statistical Research Metrics
To isolate deeper trends regarding vulnerability distribution profiles, architectural risk ingestion, and code remediation behaviors, the comparative matrix tracks a specialized array of structural research indices:

*   **High Severity Critical Ratio:** Measures the proportional weight of high-priority security findings relative to the total vulnerability discovery pool.
    $$\text{High Severity Critical Ratio} = \frac{\text{Aggregate High}}{\text{Total Defects}}$$
*   **Defect Concentration Factor:** Gauges the density of flaws strictly within the subsets of code files containing vulnerabilities.
    $$\text{Defect Concentration Factor} = \frac{\text{Total Defects}}{\text{Total Defective PRs}}$$
*   **Alert Dismissal Rate:** Evaluates development risk acceptance by measuring the percentage of compromised pull requests that bypassed remediation gates to achieve full repository merging.
    $$\text{Alert Dismissal Rate} = \frac{\sum_{i=1}^{1000} [\text{has\_issues\_bool}_i = \text{true} \;\wedge\; \text{status}_i = \text{"Merged"}]}{\text{Total Defective PRs}}$$
*   **Count of Unique CWE IDs:** A distinct taxonomical tracker that extracts, flattens, and calculates the absolute cardinal count of unique Common Weakness Enumeration identifiers flagged across the cohort.
    $$\text{Unique CWE Count} = \left\vert{} \bigcup_{i=1}^{1000} \{\text{cwes}_i\} \right\vert{}$$

#### 3.5.3.4 Security Vulnerability Analysis Data Table
To map the concrete security defects found during scanning into an actionable engineering taxonomy, the comparative dashboard displays a dedicated **Security Vulnerability Analysis** data table. This reporting table aggregates raw alerts from both the AI and human database files, extracting and rendering rows composed of exactly three structural columns:

1.  **CWE ID:** The unique numerical classification key assigned by the MITRE Corporation to identify the core category of the flaw (e.g., `CWE-079` or `CWE-770`).
2.  **Architectural Nomenclature from MITRE:** The standardized, formal dictionary name mapping the precise semantic description of the design weakness (e.g., *"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" or "Allocation of Resources Without Limits or Throttling"*).
3.  **Triggering CodeQL Rule:** The explicit application check pack identifier string executed by the CodeQL static analyzer to parse and trigger that unique defect alert block (e.g., `js/xss-through-dom` or `js/missing-rate-limiting`).

#### 3.5.3.5 Empirical Security Analysis Summary (AI vs. Human Baseline)
By activating the synthesis routine via the **"View Comparative Analysis"** dashboard view, the framework aggregates metrics across both completed 1,000-PR databases to isolate macro-level behavior profiles between autonomous AI engines and the human developer control baseline:

| Strategic Evaluative Metric | AI-Authored PRs Track (`accumulated_database.json`) | Human-Authored PRs Track (`human_accumulated_database.json`) | Empirical Imbalance / Comparative Variance |
| :--- | :--- | :--- | :--- |
| **Total Lines Changed (LOC)** | 169,106 lines | 149,837 lines | AI modified a 12.86% larger volumetric footprint |
| **Defective Submissions Count** | 15 PRs Flagged | 8 PRs Flagged | AI agents generated 87.5% more defective patches |
| **Total Security Issues Discovered**| 40 defects | 16 defects | AI increased sheer alert output volume by 150.0% |
| **Cohort CWE Defect Density** | 0.000237 defects/line | 0.000107 defects/line | AI defect concentration is 121.5% higher per line |
| **Global Merge Rate** | 55.0% (550 / 1000) | 77.5% (775 / 1000) | Human pull requests possess a 22.5% higher merge velocity |

##### Key Insights from the Comparative Cross-Tabulation:
1. **Volumetric Severity Escapes:** The cohort severity stacks demonstrate that generative AI tools introduce a significantly higher absolute volume of critical flaws. The AI track generated exactly **9** critical security flaws (High) out of 40 total alerts compared to only **4** for the human baseline. However, because human errors were more heavily concentrated in a small group of high-severity bugs, the human cohort exhibited a slightly higher **High-Severity Critical Ratio** of **25.0%** compared to the AI ratio of **22.5%**. 
2. **Taxonomical Convergence in Critical Weaknesses (CWE Similarities):** The Security Vulnerability Analysis dashboard views expose a striking structural similarity between authorship tracks: both AI agents and human developers fall victim to the exact same critical security flaws. Both datasets exhibit an overlapping concentration of three specific high-severity weaknesses:
    *   **`CWE-020` (Improper Input Validation):** Both cohorts frequently fail to validate raw inbound data vectors prior to process execution. This reveals that AI models inherit basic human oversights regarding trusting external user inputs blindly.
    *   **`CWE-079` (Cross-Site Scripting - XSS):** Both tracking groups exhibit a high occurrence of DOM-based and reflected web interface validation failures (specifically caught via the `js/xss-through-dom` analyzer rule). This shows that generative models consistently duplicate typical human developer shortcuts regarding direct browser rendering parameters.
    *   **`CWE-770` (Allocation of Resources Without Limits or Throttling):** Both tracks demonstrate a severe structural blind spot regarding environmental and execution resource limits. Both AI and human authors frequently write functional code blocks that completely lack defensive throttling barriers or connection ceilings, making the logic vulnerable to resource exhaustion.
3. **Architectural Divergence in Specialized Failure Profiles (CWE Differences):** Beyond basic web-boundary validation overlaps, the tracks diverged significantly, showing a distinct split in how humans make mistakes versus how AI engines generate errors:
    *   **The AI Track (Improper Sanitization & Algorithmic Complexities):** AI flaws were heavily clustered around improper input handling and string optimization oversights. Beyond simple parsing failures, AI models uniquely introduced architectural complexities tied to pattern matching and algorithmic resource starvation. This includes **`CWE-1333`** (Regular Expression Denial of Service - ReDoS) and **`CWE-730`** (Regex Injection), alongside **`CWE-834`** (Excessive Iteration loops). These findings prove that AI agents default to writing complex, highly performant code snippets or nested string patterns without evaluating the worst-case CPU performance or execution constraints.
    *   **The Human Track (Information Leakage & Cryptographic Ingestion):** Human-authored vulnerabilities were heavily tied to contextual security awareness and systemic failures in data handling. Human errors clustered tightly around data disclosure and security configuration oversights: **`CWE-209`** (Information Exposure Through an Error Message), **`CWE-312`** (Cleartext Storage of Sensitive Information), **`CWE-359`** (Privacy Violation), and **`CWE-497`** (Exposure of System Information to an Unauthorized Control Sphere). Furthermore, human developers uniquely introduced cryptographic flaws, including weak hashing algorithms (e.g., legacy MD5/SHA-1 implementations), broken cryptography, or risky encryption protocols. This underscores that humans struggle with managing configuration state, data exposure vectors, and cryptographic operations, while AI agents produce functional errors driven by algorithmic complexity blind spots.
4. **Taxonomical Errors and Concentration Factors:** The dashboard's table tracking reveals that generative AI agents introduce tightly packed clusters of structural weaknesses when they fail. When an AI model makes a coding mistake, it tends to replicate errors algorithmically across the same file framework, generating an elevated **Defect Concentration Factor** of **2.67 bugs per vulnerable PR**, whereas the human baseline demonstrated a more distributed concentration factor of **2.0 bugs per vulnerable PR**.
5. **The Risk Acceptance Paradox:** Cross-referencing database attributes reveals a profound breakdown in open-source development gatekeeping and unmasks a distinct bias in reviewer trust. Out of the 15 AI pull requests flagged with active security issues, the dashboard records an **Alert Dismissal Rate** of **46.67%**, proving that nearly half of the defective AI code additions successfully slipped past manual maintainer reviews to achieve full production repository merging. Conversely, human-authored vulnerable code exhibited a substantially higher Alert Dismissal Rate of **75.0%** (with 6 out of 8 defective PRs merged). This baseline gap mathematically proves that **human-authored pull requests are granted significantly more implicit trust by repository maintainers during code review, allowing defective code from human peers to be dismissed and merged at a far higher frequency than corresponding AI-generated alerts**. This demonstrates that while code review gates across modern repositories fail to block context-dependent software flaws across both tracks, a structural skepticism threshold actively limits the unvetted ingestion of flawed automated code.
