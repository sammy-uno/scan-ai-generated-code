# Chapter 5: Empirical Results & Discussion

## 5.1 Comparative Evaluation Metrics and Statistical Indicators
To ensure absolute mathematical transparency and isolate deeper trends regarding vulnerability distribution profiles, architectural risk ingestion, and code remediation behaviors, the comparative matrix calculates and renders a dedicated set of macro performance metrics and structural research indices for each 1,000-PR tracking cohort:

* **Total Volumetric Footprint (Lines of Code):** Calculated as the cumulative summation of the net lines of code altered across the complete cohort of 1,000 pull requests:
$$\text{Total LOC} = \sum_{i=1}^{1000} \text{loc}_i$$

* **Total Defective Pull Requests:** A summation tracker recording the absolute count of pull requests where the PR json field `has_issues_bool` flag evaluates to true.<br/>
  $$\text{Total Defective PRs} = \sum_{i=1}^{1000} (\text{has issues bool}_i = \text{true})$$

* **Pull Request Lifecycle Status Distribution:** A discrete categorization split showing the exact resolution status sums for open, merged, and closed states across the cohort.<br/>

$$\text{Total Open} = \sum_{i=1}^{1000} (\text{status}_i = \text{Open}) \qquad \text{Total Merged} = \sum_{i=1}^{1000} (\text{status}_i = \text{Merged}) \qquad \text{Total Closed} = \sum_{i=1}^{1000} (\text{status}_i = \text{Closed})$$

* **Total Defects Output Volume:** Establishes the absolute volume of unique security findings discovered across all inspected files within the tracking cohort:
$$\text{Total Defects} = \sum_{i=1}^{1000} (h_i + m_i + l_i)$$

* **Cohort CWE Defect Density:** Represents the foundational safety density metric of the cohort, modeling the total discovered defects directly against the absolute volumetric footprint of line changes:
$$\text{Cohort Defect Density} = \frac{\text{Total Defects}}{\text{Total LOC}}$$

* **Average Defect Rate:** Computes the mean mathematical frequency of security flaws encountered per individual pull request submission:
$$\text{Average Defect Rate} = \frac{\text{Total Defects}}{1000}$$

* **Global Merge Rate:** The exact mathematical proportion of contributions that successfully pass development branch review to achieve full production lifecycle merging:
$$\text{Global Merge Rate} = \frac{\text{Total Merged PRs}}{1000}$$

* **Aggregate Vulnerabilities Severity Stack:** Isolates the standalone absolute volume of issues separated neatly into their localized threat priority classifications:
$$\text{Aggregate High} = \sum_{i=1}^{1000} h_i, \quad \text{Aggregate Medium} = \sum_{i=1}^{1000} m_i, \quad \text{Aggregate Low} = \sum_{i=1}^{1000} l_i$$

* **High Severity Critical Ratio:** Measures the proportional weight of high-priority security findings relative to the total vulnerability discovery pool:
$$\text{High Severity Critical Ratio} = \frac{\text{Aggregate High}}{\text{Total Defects}}$$

* **Defect Concentration Factor:** Gauges the density of flaws strictly within the isolated subsets of code files that contain active vulnerabilities:
$$\text{Defect Concentration Factor} = \frac{\text{Total Defects}}{\text{Total Defective PRs}}$$

* **Alert Dismissal Rate:** Evaluates development risk acceptance by measuring the percentage of compromised pull requests that bypassed remediation gates to achieve full repository merging.<br/>
  $$\text{Alert Dismissal Rate} = \frac{\sum_{i=1}^{1000} (\text{has issues bool}_i = \text{true} \;\wedge\; \text{status}_i = \text{Merged})}{\text{Total Defective PRs}}$$

* **Count of Unique CWE IDs:** A distinct taxonomical tracker that extracts, flattens, and calculates the absolute cardinal count of unique Common Weakness Enumeration identifiers flagged across the cohort:
$$\text{Unique CWE Count} = \left\vert{} \bigcup_{i=1}^{1000} \{\text{cwes}_i\} \right\vert{}$$

### 5.2 Comparative Statistical Analysis of AI and Human Cohorts
To isolate macro-level behavior profiles and systemic security trends, the framework executes a cross-cohort synthesis that evaluates the aggregated database telemetry of both the automated AI agents and the human developer control baseline.

| Strategic Evaluative Metric | AI-Authored PRs Track (`accumulated_database.json`) | Human-Authored PRs Track (`human_accumulated_database.json`) | Empirical Imbalance / Comparative Variance |
| :--- | :--- | :--- | :--- |
| **Total Lines Changed (LOC)** | 169,106 lines | 149,837 lines | AI modified a 12.86% larger volumetric footprint |
| **Defective Submissions Count** | 15 PRs Flagged | 8 PRs Flagged | AI agents generated 87.5% more defective patches |
| **Total Security Issues Discovered**| 40 defects | 16 defects | AI increased sheer alert output volume by 150.0% |
| **Cohort CWE Defect Density** | 0.000237 defects/line | 0.000107 defects/line | AI defect concentration is 121.5% higher per line |
| **Global Merge Rate** | 55.0% (550 / 1000) | 77.5% (775 / 1000) | Human pull requests possess a 22.5% higher merge velocity |

### 5.3 Core Analytical Insights and Security Divergences
Beyond the global statistical metrics, cross-tabulating the distinct vulnerability profiles of AI agents and human developers reveals the precise structural vectors driving code quality defects. This deep dive isolates how autonomous code generation errors differ fundamentally from human developer oversights when operating in active software repositories. To map out these variations, the analytical results are categorized into five operational security dimensions: volumetric severity escapes, common taxonomical failures, distinct architectural divergences, defect clustering density factors, and the behavioral mechanics of the risk acceptance paradox.

#### 5.3.1 Volumetric Severity Escapes
The severity tracking profiles prove that generative AI agents introduce a significantly higher concentration of critical flaws compared to the human baseline. The AI track generated exactly **21 critical security flaws (High)** out of 40 total alerts, resulting in a high **High-Severity Critical Ratio of 52.5%**. Conversely, the human-authored control track produced **7 critical security flaws (High)** out of 16 total alerts, yielding a lower **High-Severity Critical Ratio of 43.75%**. This structural shift demonstrates that autonomous code generation engines are significantly more prone to introducing structural security flaws that scale directly into severe, high-impact exploit vectors rather than minor code quality warnings or superficial code smells.

#### 5.3.2 Taxonomical Convergence in Critical Weaknesses (CWE Similarities)
The comparative data uncovers a striking structural similarity between authorship tracks: both AI agents and human developers fall victim to the exact same critical security flaws. Both datasets exhibit an overlapping concentration of three specific high-severity weaknesses:
* **`CWE-020` (Improper Input Validation):** Both cohorts frequently fail to validate raw inbound data vectors prior to process execution, showing that AI models inherit basic human oversights regarding trusting external user inputs blindly.
* **`CWE-079` (Cross-Site Scripting - XSS):** Both tracking groups exhibit a high occurrence of DOM-based and reflected web interface validation failures, specifically caught via the `js/xss-through-dom` analyzer rule. This shows that generative models consistently duplicate typical human developer shortcuts regarding direct browser rendering parameters.
* **`CWE-770` (Allocation of Resources Without Limits or Throttling):** Both tracks demonstrate a severe structural blind spot regarding environmental and execution resource limits. Both AI and human authors frequently write functional code blocks that completely lack defensive throttling barriers or connection ceilings, making the logic vulnerable to resource exhaustion.

#### 5.3.3 Architectural Divergence in Specialized Failure Profiles (CWE Differences)
Beyond basic web-boundary validation overlaps, the tracks diverged significantly, showing a distinct split in how humans make mistakes versus how AI engines generate errors:
* **The AI Track (Improper Sanitization & Algorithmic Complexities):** AI flaws were heavily clustered around improper input handling and string optimization oversights. Beyond simple parsing failures, AI models uniquely introduced architectural complexities tied to pattern matching and algorithmic resource starvation. This includes **`CWE-1333`** (Regular Expression Denial of Service - ReDoS) and **`CWE-730`** (Regex Injection), alongside **`CWE-834`** (Excessive Iteration loops). These findings prove that AI agents default to writing complex, highly performant code snippets or nested string patterns without evaluating the worst-case CPU performance or execution constraints.
* **The Human Track (Information Leakage & Cryptographic Ingestion):** Human-authored vulnerabilities were heavily tied to contextual security awareness and systemic failures in data handling. Human errors clustered tightly around data disclosure and security configuration oversights: **`CWE-209`** (Information Exposure Through an Error Message), **`CWE-312`** (Cleartext Storage of Sensitive Information), **`CWE-359`** (Privacy Violation), and **`CWE-497`** (Exposure of System Information to an Unauthorized Control Sphere). Furthermore, human developers uniquely introduced cryptographic flaws, including weak hashing algorithms (e.g., legacy MD5/SHA-1 implementations), broken cryptography, or risky encryption protocols. This underscores that humans struggle with managing configuration state, data exposure vectors, and cryptographic operations, while AI agents produce functional errors driven by algorithmic complexity blind spots.

#### 5.3.4 Spatial Clustering and Concentration Factors
The tracking arrays reveal that generative AI agents introduce tightly packed clusters of structural weaknesses when they fail. When an AI model makes a coding mistake, it tends to replicate errors algorithmically across the same file framework, generating an elevated **Defect Concentration Factor** of **2.67 bugs per vulnerable PR**. Conversely, the human baseline demonstrated a more distributed concentration factor of **2.0 bugs per vulnerable PR**, showing that human mistakes are more isolated across application layers.

#### 5.3.5 Unmasking the Risk Acceptance Paradox
Cross-referencing database attributes reveals a profound breakdown in open-source development gatekeeping and unmasks a distinct bias in reviewer trust. Out of the 15 AI pull requests flagged with active security issues, the dashboard records an **Alert Dismissal Rate** of **46.67%**, proving that nearly half of the defective AI code additions successfully slipped past manual maintainer reviews to achieve full production repository merging. 

Conversely, human-authored vulnerable code exhibited a substantially higher Alert Dismissal Rate of **75.0%** (with 6 out of 8 defective PRs merged). This baseline gap mathematically proves that **human-authored pull requests are granted significantly more implicit trust by repository maintainers during code review, allowing defective code from human peers to be dismissed and merged at a far higher frequency than corresponding AI-generated alerts**. This demonstrates that while code review gates across modern repositories fail to block context-dependent software flaws across both tracks, a structural skepticism threshold actively limits the unvetted ingestion of flawed automated code.
