# 📊 AI & Human Scanner System Architecture Anchor

> **System Note for AI Assistants:** This repository utilizes a split-file parallel matrix layout. Core code analysis parsing loop workflows are strictly separated from inline YAML definitions to maximize platform execution speed, eliminate truncation limits, and prevent hidden character escaping traps.

## 🛠️ Repository File Tree Map
1. **`.github/workflows/codeql-scan.yml`**: Automated pipeline fanning out to scan up to 20 AI pull requests concurrently in a parallel matrix layout loop. Runs `scripts/ai-scanner.py` to seed target tasks.
2. **`.github/workflows/human-codeql-scan.yml`**: Manual companion auditing pipeline fanning out to scan up to 20 user-specified manual pull requests concurrently. Invokes `scripts/human-scanner.py` to seed tasks.
3. **`.github/workflows/compare-scans.yml`**: Global cross-workflow aggregation pipeline. Reaches across history trees using GitHub REST API abstractions to sync matching datasets side-by-side.
4. **`scripts/ai-scanner.py`**: Reads `aidev_scan_list.csv` dynamically, tracks structural boundaries (<1000 line changes), and feeds the parent automated matrix.
5. **`scripts/human-scanner.py`**: Reads `human_scan_list.csv` dynamically and injects a balanced fallback `agent_name: "Human_Auditor"` token payload key to preserve data format paths.
6. **`scripts/parse-results.py`**: Individual matrix block row processor. Evaluates results natively at the step tier and writes localized details to `$GITHUB_STEP_SUMMARY`.
7. **`scripts/consolidate-report.py`**: Workflow summary engine. Merges fanned runner artifacts and tracks query properties.
8. **`scripts/compare-reports.py`**: Comparative analysis engine. Synchronizes fanned automated results with human audit results to produce macro group metrics comparisons.

## ⚠️ Matrix Reporting & Layout Rules
* **Parallel Status Constraints**: Step-level protections (`continue-on-error: true` inside worker tasks) are used to absorb local platform cuts or tool exceptions gracefully, ensuring the overarching workflow visual card box status settles to a perfect Green.
* **The CWE Top 25 Threat Matrix**: Both `consolidate-report.py` and `compare-reports.py` use a standardized, automated risk inflation array check. If a CodeQL vulnerability maps to any CWE ID on the industry-standard Top 25 Most Dangerous list, its severity display badge is inflated to **🔴 High**, overriding standard `warning` levels.
* **Conditional Column Hiding Engine**: `consolidate-report.py` utilizes smart `SCAN_TYPE` environment variable detection. When running a manual human scan (`SCAN_TYPE: "human"`), it automatically drops the **"AI Tool"** column header and its corresponding dataset cells to keep rows clean.
* **Historical Scoping Engine**: `compare-scans.yml` utilizes direct `github.rest.actions.listWorkflowRuns` filters. It scans the absolute latest completed run IDs for both tracking paths to pull exactly active datasets, preventing old historical artifact caches from inflating comparison totals.
