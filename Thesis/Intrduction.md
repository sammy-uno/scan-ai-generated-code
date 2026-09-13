## 1.3 Research Questions (RQs)
To achieve the empirical objectives of our comparative security analysis, we structure our evaluation of vulnerabilities in agentic and human-centric pull requests within the AIDev dataset around four foundational research questions:

* **RQ1:** Utilizing an automated Static Application Security Testing (SAST) tool, how do agentic and human pull requests quantitatively compare across core security metrics—specifically total defect volume, vulnerable pull request frequency, mean lines of code (LOC) modified, and normalized defect density?
* **RQ2:** Utilizing the MITRE CWE Top 25 classification framework, how do agentic and human pull requests qualitatively differ across vulnerability severity profiles, and which track presents a statistically higher concentration of critical software security flaws?
* **RQ3:** Based on the discovered vulnerability profiles, what are the core taxonomic commonalities and structural divergences in software weaknesses when contrasting agent-authored pull requests against the human baseline?
* **RQ4:** How does an open-source repository maintainer's implicit trust bias impact final pull request lifecycle resolutions (merge versus closure rates) when managing vulnerable code contributions, and does it lead to a higher risk acceptance rate for human-authored versus agentic pull requests?
