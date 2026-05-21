# 📊 AI Scanner Pipeline Architecture Baseline

> **System Note for AI Assistants:** This repository runs a highly sophisticated, three-stage dynamic matrix vulnerability scanning pipeline for GitHub Pull Requests. Read this document to understand the files, syntax safeguards, and exact execution flow.

## 🛠️ Repository File Manifest

1. **`.github/workflows/codeql-scan.yml`**: Automated workflow triggered via `workflow_dispatch`. Coordinates the Discover ➡️ Analyze (Parallel Matrix Fan-out) ➡️ Report phases.
2. **`scripts/ai_scanner.py`**: Reads `aidev_scan_list.csv`, uses `gh pr view` to fetch line additions/deletions, filters out bloated PRs (>1000 lines), and prints a dynamic JSON matrix configuration string to `$GITHUB_OUTPUT`.
3. **`scripts/parse-results.py`**: Intercepts local CodeQL SARIF output results during matrix step execution and maps rule tags against the **CWE Top 25 Vulnerability Matrix** to generate isolated execution tables.

---

## ⚠️ Critical Engineering Safeguards (Do Not Break)

### 1. The Empty Location Array Bug ('list' object has no attribute 'get')
* **The Root Cause**: When CodeQL flags a global property or architecture metric, it emits an empty array `[]` for the `locations` property in the SARIF file rather than a dictionary.
* **The Safeguard**: Every loop parsing `results.sarif` (both in `parse-results.py` and the inline Python of the `report` job) must use this exact type-safe conditional check before calling `.get()`:
  ```python
  locs_data = result.get('locations', [])
  locs = {}
  if isinstance(locs_data, list) and len(locs_data) > 0:
      first_loc = locs_data[0]
      locs = first_loc.get('physicalLocation', {}) if isinstance(first_loc, dict) else {}
  elif isinstance(locs_data, dict):
      locs = locs_data.get('physicalLocation', {})
  ```

### 2. Inline Python Shell Escaping (Line 99 Syntax Crash)
* **The Root Cause**: The `report` job runs inside a bash wrapper via `python3 -c "..."`. Using double quotes `""` for Python strings inside this wrapper breaks the bash command string declaration.
* **The Safeguard**: All string declarations inside the inline Python block (such as severity badges) **must use single quotes `''`**:
  ```python
  if h > 0: row_severity_badge = '🔴 High'
  elif m > 0: row_severity_badge = '🟡 Medium'
  ```

### 3. Dynamic Checkout Isolation
* **The Root Cause**: Matrix workers checkout third-party public repositories using `ref: refs/pull/${{ matrix.pr_num }}/head`. This completely wipes out the root workspace files, deleting the repository's parsing scripts.
* **The Safeguard**: The workflow copies repository utility scripts safely out of the blast radius into `/tmp/scripts/` right before running the third-party git checkout, then restores them instantly.

---

## 📊 Dashboard Summary Format Requirements
The final report must render a global markdown summary layout utilizing the following synchronized color configurations:
* `🔴 High` / `🔴 H`: Severity level `error` or matching any `CWE_TOP_25` definition array element.
* `🟡 Medium` / `🟡 M`: Severity level `warning`.
* `🔵 Low` / `🔵 L`: Severity level `note` / `recommendation`.
* `🟢 Clean`: Zero security vulnerabilities discovered.

---

## 🚀 How to Resume in a New Session
When initializing a new session with an AI model, paste this exact instruction:
> *"We are working on the project mapped out in `.github/AI_CONTEXT.md`. I have established a three-stage automated pipeline that leverages a dynamic parallel matrix to execute custom CodeQL validation scans against public pull requests. Please follow the explicit type-safe dictionary filters and shell escaping constraints documented there for all future file generations."*
