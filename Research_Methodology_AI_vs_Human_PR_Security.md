# Methodology: Comparative Security Analysis of AI and Human PRs
<br/>

The following is the methodology used for assessing the security vulnerabilities in AI-Agent and Human pull requests within the AIDev Dataset:

### Step 1: Dataset Selection & Filtering

For my research into human-AI collaboration, I am leveraging the AIDev dataset hosted on Hugging Face. This platform serves as a comprehensive repository of AI-generated pull requests, documenting both the source code proposed by AI agents and their subsequent interactions with human reviewers. To evaluate code quality through the lens of security vulnerabilities, this study performs a comparative analysis between AI and human PRs using GitHub CodeQL. To mitigate noise and ensure data relevance, the scope is narrowed to the AIDev-Pop subset. This specialized corpus isolates high-quality code changes deployed within established, popular repositories with over 100 stars. Human pull requests are extracted from the exact repositories hosting the Agentic-PRs. To guarantee data relevance and avoid noise from inactive, empty, or personal projects, a strict threshold was set: only repositories with over 500 stars were included in the human baseline. This filtering strategy deliberately excludes low-quality or beginner-level test repositories, ensuring a more rigorous comparison.
