### Table 5.1: Master Comparative Statistical Overview
*(Aggregated Results Across 2,000 Total PRs and 23 Discovered Unique CWEs)*

| Strategic Evaluative Metric | AI Track | Human Track | Unit | Core Security Takeaway |
| :--- | :---: | :---: | :---: | :--- |
| **Total Pull Requests Audited** | 1,000 | 1,000 | PRs | Establishes a balanced, symmetrical sampling size necessary for rigorous statistical cohort analysis. |
| **Total Volumetric Footprint** | 169,106 | 149,837 | Lines of Code | AI modified 12.86% more source text. |
| **Defective Submissions Count** | 15 | 8 | PRs Flagged | AI generated 87.5% more vulnerable pull requests. |
| **Total Security Issues Discovered** | 40 | 16 | Alerts Found | AI-generated pull requests produced 150.0% more security vulnerabilities than the human baseline. |
| **Cohort Defect Density** | 2.37 | 1.07 | Bugs / 10k LOC | AI-generated code has a 121.5% higher vulnerability density than human-authored code. |
| **Defect Concentration Factor** | 2.67 | 2.00 | Bugs / Broken PR | AI-vulnerable contributions inject multiple defects per broken pull request. |
| **Unique CWE Categories** | 15 | 15 | Unique CWEs | Each track exposed an identical variety of 15 distinct CWE categories, with exactly 7 vulnerability types overlapping across both cohorts. |
| **High-Severity Defect Volume** | 21 | 7 | High Alerts | AI-generated contributions produced exactly three times the volume of critical, high-impact vulnerabilities compared to human authors. |
| **Medium-Severity Defect Volume** | 19 | 9 | Medium Alerts | AI-generated pull requests produced more than double the volume of medium-severity vulnerabilities compared to the human baseline. |
| **Low-Severity Defect Volume** | 0 | 0 | Low Alerts | The patch-coordinate filtering pipeline effectively isolated active risks, yielding zero low-severity noise across both tracks. |
| **High-Severity Critical Ratio** | 52.50% | 43.75% | % of total defects | Both tracks exhibit an elevated risk posture, with nearly half of human defects and over half of AI defects qualifying as high-severity flaws. |
| **Global PR Merge Rate** | 55.00% | 77.50% | PRs | Human-authored pull requests maintain a 22.50% higher acceptance rate, achieving significantly higher overall baseline deployment velocity. |
| **Alert Dismissal Rate** | 46.67% | 75.00% | % of Vulnerable PRs | Exposes the Risk Acceptance Paradox: maintainers bypass review gates for three-quarters of flawed human additions due to implicit social trust shortcuts. |
