Progress Update 9/1/2026

To evaluate the security profiles of artificial intelligence versus human developers at scale, 
the vulnerability scanning pipeline was expanded to analyze 1,000 Pull Requests (PRs) from each respective track within the AIDev dataset. 
To mitigate resource constraints and execution timeouts imposed by the GitHub Actions runner environment, a batch-processing orchestration strategy was implemented. 
The 2,000 total PRs were split into uniform batches of 250 PRs per run. Upon the completion of each operational block, 
the extracted vulnerability telemetry was compiled and incrementally appended to a centralized JSON database.

For a comprehensive overview of the analysis architecture, the complete scanning methodology is detailed in the accompanying [Security Pipeline and Dashboard Specification](./security-pipeline-and-dashboard.md).

Executing the CodeQL vulnerability analysis across a dataset of 2,000 Pull Requests (divided into four uniform batches of 250 PRs per track) introduced significant computational overhead. 
The cumulative analysis required approximately 10 hours of processing time, split equally between the AI-agent and human developer cohorts. Furthermore, achieving an uninterrupted, 
deterministic execution pipeline presented substantial technical hurdles, necessitating multiple optimization iterations to refine the environment configuration and ensure robust data ingestion. 

To isolate vulnerabilities introduced exclusively by the Pull Request (PR) modifications, a precise coordinate filtering layer was implemented. 
This optimization filters out all static analysis defects (CWEs) residing outside the scope of the immediate patch boundaries. 
By focusing strictly on the code delta, this approach eliminates the need to execute dual baseline scans—first on the original repository and again post-PR—to isolate pre-existing technical debt. 
Consequently, the analysis considers only those vulnerabilities whose line coordinates intersect directly with the specific line additions or deletions introduced in the PR. 
The technical design details of this analysis pipeline and its underlying architecture are comprehensively explained in the Security Pipeline and Dashboard Specification. 

<img> 

To make it easy to view the scanning results and compare them side by side, I created dashboards to display the scanning result of each track. 
Another global comparative summary was also developed to vie all the metrics from my security analysis.

You can access the dashboards from this link. 

Please review my methodology and the results metrics and let me know if you have any questions. 

I would like to focus in writing my thesis since it needs to be completed and submitted in the next few weeks. 


