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
