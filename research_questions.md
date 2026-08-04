**Based on your complete architecture—the AIDev dataset, CodeQL automated scanning, line-level change tracking, and side-by-side human auditing—your thesis sits at the intersection of Generative AI Safety, Empirical Software Engineering, and Automated Vulnerability Management.**



# 📑 Thesis Research Questions (RQs)
## AI-Agentic Software Engineering vs. Human Developer Security Analysis

### 🔍 RQ1: Vulnerability Density & Severity Profile
**Research Question:** 
How does the security debt introduced by agentic AI software developers compare to that of human developers in open-source repositories?

*   **Academic Rationale:** This establishes the foundational baseline of your research. It uses your pipeline's metrics to analyze if AI agents introduce statistically more security flaws than humans per line of code.
*   **Pipeline Data Feed:** Driven by the `cwe_density` ratio calculation (`total_issues / live_loc`) and the severity accumulation dictionary (`high`, `medium`, `low`) built inside `compare-reports.py`.
*   **Thesis Metric Focus:** 
    *   Mean Vulnerability Density (Alerts per 1,000 LOC).
    *   Severity Distribution Ratio (Evaluating if AI code is skewed toward low-impact warnings or high-severity errors).

---

### 🛡️ RQ2: The CWE Top 25 Threat Proximity
**Research Question:** 
To what extent do AI-generated code modifications introduce high-risk vulnerabilities tracking against the industry-standard CWE Top 25 Most Dangerous Software Weaknesses?

*   **Academic Rationale:** Not all vulnerabilities carry equal weight. This question evaluates if AI agents are prone to introducing the most critical, easily exploitable architectural bugs (like SQL Injection or Use-After-Free) compared to human omissions.
*   **Pipeline Data Feed:** Powered directly by your automated **CWE Top 25 Threat Matrix array override** built into `parse-results.py`, which flags matching tags and forces their display badge to `🔴 High`.
*   **Thesis Metric Focus:**
    *   Top 25 CWE Prevalence Rate (Percentage of total AI alerts that map to the Top 25 matrix).
    *   Taxonomy Mapping (Frequency charts sorting specific CWE IDs introduced by agents like Devin or Claude Code vs. Human counterparts).

---

### 🧠 RQ3: Human Auditor Detection Deficit
**Research Question:** 
What is the delta between vulnerabilities caught by automated semantic analysis (CodeQL) and the rejection reasons documented by human code reviewers for AI-generated pull requests?

*   **Academic Rationale:** This explores the "blind spots" of human reviewers when auditing AI code. If CodeQL catches a verified CWE on lines modified by an AI agent, but human reviewers merged the PR anyway, it proves a measurable gap in manual human code review vigilance.
*   **Pipeline Data Feed:** Maps the output of `consolidate-report.py` against the original `all_pull_request.parquet` metadata from the AIDev dataset (cross-referencing human comments and final PR merge states).
*   **Thesis Metric Focus:**
    *   Human Reviewer Escape Rate (The percentage of CodeQL-verified vulnerabilities that slipped past humans into a `🟣 Merged` state).
    *   Reviewer Fatigue Correlation (Analyzing if escape rates increase as the size of the PR (`PR_LOC`) increases).

---

### 🔄 RQ4: Lifecycle Longevity & Security Debt Persistence
**Research Question:** 
How does the lifecycle status (Open, Closed, Merged) of a pull request correlate with the security density of the code introduced, and do vulnerable AI patches persist longer in active code streams than human patches?

*   **Academic Rationale:** This looks at the operational lifecycle impact of these vulnerabilities. It evaluates whether repositories are successfully shutting down or fixing insecure AI PRs, or if they are lingering as active security debt.
*   **Pipeline Data Feed:** Driven by your live API hooks `get_live_pr_status` and `gh pr view --json state` tracking the `open`, `closed`, and `merged` counters inside `compare-reports.py`.
*   **Thesis Metric Focus:**
    *   Survival Analysis of Insecure PRs (Time-to-close or merge for vulnerable vs. clean AI patches).
    *   Merge Ratio of Insecure Code (What percentage of total accepted AI code units contained active vulnerabilities?).
 

# Documentation 

# 📑 Thesis Methodology Summary: Part 1
## Dual-Track Differential Semantic Security Analysis Matrix

To empirically evaluate the security debt introduced by agentic AI software developers relative to human developers, this thesis leverages a novel **split-file parallel matrix framework**. By isolating and parsing code changes across thousands of open-source pull requests (PRs) sourced from the **AIDev dataset**, the methodology establishes a highly normalized, reproducible environment for automated static analysis. 

The core infrastructure consists of a multi-tier data pipeline executed natively on GitHub Actions and orchestrated via the GitHub CLI API.

---

### 1. Target Data Ingestion & Matrix Discovery
The analysis is split into two structurally synchronized data acquisition streams to eliminate platform execution limits and hidden character escaping anomalies:
* **The Automated AI Stream (`ai-scanner.py`)**: Dynamically parses the AIDev dataset (`aidev_scan_list.csv`) across agents such as Devin, Cursor, and Claude Code.
* **The Manual Human Auditor Baseline Stream (`human-scanner.py`)**: Interrogates a balanced control group of human pull requests (`human-scan_list.csv`), injecting a hardcoded metadata token (`agent_name: "Human_Auditor"`) to maintain downward dataset schema invariance.

Both discovery nodes enforce identical strict telemetry guards: they programmatically eliminate all duplicate repository hammering, exclude pre-filtered problematic mega-repos, and apply a **Zero-Change Exclusion Guard** that discards any PR yielding 0 lines of total modifications. Furthermore, an upper-bound boundary condition filters out pull requests exceeding 1,000 lines of code (LOC) to isolate atomic developer patches and prevent semantic analysis timeouts.

# 📑 Thesis Methodology Summary:
## 2. Strict File-Level Delta Gating Engine (Overview & Architecture)

Standard static analysis sweeps assess an entire repository baseline. That operational flaw would pollute this research with years of pre-existing legacy security debt. To isolate *only* the vulnerabilities actively introduced by the pull request author, this methodology implements a strict **File-Level Delta Gating Engine** inside the worker processing tier (`parse-results.py`).

The structural logic flow operates inside the runner loop according to the following execution path:

| Execution Stage | Input Data Stream A | Input Data Stream B |
| :--- | :--- | :--- |
| **Stage 1: Ingestion** | `Raw CodeQL Alerts Generated` | `gh pr view API Path Capture` |
| **Stage 2: Parsing** | Isolated Vulnerability Path | True Modified Files Array |
| **Stage 3: Decision** | **[ Evaluate ]** | **Is trailing path slice aligned?** |
| **Decision: YES** | 🟢 **Keep Alert** | Vulnerability belongs to active PR changes. |
| **Decision: NO** | ❌ **Filtered Out** | Ambient or historical repository baseline noise is purged. |

The filtering automation executes three distinct mapping phases inside the processing engine:

1. **API Interrogation**: The system calls the GitHub CLI (`gh pr view {num} --repo {repo} --json files`) inside the transient workspace to build an absolute source-of-truth array tracking true modified relative paths.
2. **Structural Array Segmentation**: Source paths derived from the static compiler and relative paths returned by the API changed-files engine are split into matching subdirectory string arrays via a forward-slash separator (`/`). All platform backslashes are replaced and strings are forced to lowercase to block casing mismatch anomalies.
3. **End-to-End Segment Verification**: The engine evaluates the trailing slice of the alert directory segment against the complete changed-file path sequence array. If a strict segment boundary match is confirmed, the vulnerability is logged as a pure PR-introduced flaw. All loose legacy or ambient repository alerts are discarded from the thesis metrics.


# 📑 Thesis Methodology Summary:
## 3. Threat Escalation & Normalization Matrix

Once the vulnerabilities are isolated, the pipeline handles data serialization and analytical risk normalization:
* **The CWE Top 25 Threat Matrix**: To control for risk severity, both `parse-results.py` and `compare-reports.py` parse individual alert tags against the industry-standard CWE Top 25 Most Dangerous Software Weaknesses. Any matching CodeQL flaw is automatically inflated to a **🔴 High Severity Error**, overriding default warning configurations.
* **The Pure Math Density Lock**: The system calculates the vulnerability density ratio as `Isolated Alerts / PR Size (LOC)`. If an asset reports a line delta of zero due to a null-change set, the density is programmatically locked to a hard `0.0` to eliminate division-by-zero math distortions.
* **Pipe Sanitization Safeguard**: Raw multi-line diagnostic descriptions are scrubbed to replace vertical table delimiters (`|` to `\|`), safeguarding Markdown syntax layout integrity.

---

### 4. Cross-Workflow History Aggregation
Because worker tasks operate inside ephemeral, parallel virtual matrix nodes, final synthesis is governed by a global comparative workflow (`compare-scans.yml`). 

Rather than relying on local context strings, this pipeline executes a live GitHub CLI query (`gh run list --status=success --limit=1`) coupled with explicit index slicing (`jq -r '..databaseId'`) to fetch the most recently completed runs for both streams. It reaches back across history trees, downloads the fanned `summary.json` outputs, and builds a comprehensive evaluation dashboard directly on the workspace runner board.

