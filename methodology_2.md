# Chapter 4: Data Analysis and Evaluation

## 4.2 Statistical Hypotheses and Testing Framework
To rigorously evaluate the security profiles of AI-generated software engineering contributions gathered by our automated ingestion platform, this study establishes a series of statistical testing criteria. Our primary goal is to determine if autonomous AI agents introduce code quality or security vulnerabilities at a higher rate compared to typical human open-source baselines.

We formalize our evaluation across two core metrics: **Vulnerability Ingestion Density ($D_v$)** and **Weakness Severity Index ($S_i$)**.

### Hypothesis 1: Vulnerability Ingestion Density ($D_v$)
The first test measures whether AI agent contributions exhibit a significantly higher density of security flaws per line of code (LOC) added to a repository compared to historical baseline data. Let $\mu_{AI}$ represent the mean security flaw density of AI-generated pull requests, and $\mu_{Base}$ represent the mean flaw density of human contributions.

$$
\begin{aligned} 
H_0 &: \mu_{AI} \le \mu_{Base} \quad \text{(Null Hypothesis: AI code contains less or equal vulnerability density than human baselines.)} \\ 
H_1 &: \mu_{AI} > \mu_{Base} \quad \text{(Alternative Hypothesis: AI code contains a significantly higher vulnerability density.)} 
\end{aligned}
$$

### Hypothesis 2: Weakness Severity Profile ($S_i$)
The second test evaluates whether the specific vulnerabilities introduced by AI agents lean toward high-severity or critical weaknesses (e.g., severe CWE categories like SQL Injection or Remote Code Execution) compared to human developers. Let $P_{AI}(\text{High})$ represent the proportion of severe flaws inside AI submissions, and $P_{Base}(\text{High})$ represent the baseline proportion.

$$
\begin{aligned} 
H_0 &: P_{AI}(\text{High}) \le P_{Base}(\text{High}) \quad \text{(Null Hypothesis: AI weaknesses do not shift toward severe profiles.)} \\ 
H_1 &: P_{AI}(\text{High}) > P_{Base}(\text{High}) \quad \text{(Alternative Hypothesis: AI weaknesses shift significantly toward high-severity categories.)} 
\end{aligned}
$$

### Hypothesis 3: Tool-Specific Performance Variance
Finally, this framework evaluates whether distinct AI tools (e.g., GitHub Copilot, Devin, Cursor) display independent variance in their generated security profiles. Let $\sigma^2_{\text{Agent}}$ represent the variance in bug densities between different autonomous tools.

$$
\begin{aligned} 
H_0 &: \sigma^2_{\text{Agent}} = 0 \quad \text{(Null Hypothesis: There is zero variance in security profiles between different AI agent tools.)} \\ 
H_1 &: \sigma^2_{\text{Agent}} > 0 \quad \text{(Alternative Hypothesis: AI tools exhibit high statistical variance in their code quality outputs.)} 
\end{aligned}
$$
