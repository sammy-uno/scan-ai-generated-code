# AIDev dataset literature review 
<br/>

The AIDev dataset serves as a comprehensive empirical research framework tracking real-world GitHub interactions between AI agents and human developers [1]. By focusing heavily on Human-AI collaboration dynamics, this taxonomy provides researchers with concrete, field-tested data on how AI coding assistants function in live repositories.

The AIDev dataset is publicly hosted on Hugging Face in Parquet format. It comprehensively tracks code contributions, review timelines, and acceptance metrics across five core commercial and open-source agent ecosystems: OpenAI Codex, Devin, GitHub Copilot, Cursor, and Claude Code.

The dataset comprises: 
* 932,791 Agent-authored pull requests (Agentic-PRs)
* 116,211 Distinct GitHub repositories
* 72,189 Human developers interacting with AI teammates

The AIDev taxonomy distinguishes between an AI agent opening a pull request and a repository maintainer merging it, emphasizing that passing a workflow test suite does not guarantee high-quality code. True integration depends on human oversight to verify code maintainability, which automated tests alone cannot guarantee.

Prior research highlights that AI-authored pull requests are frequently rejected or closed without merging due to several non-functional friction points [2]:
* **Structural Complexity:** Agents often submit over-engineered patches characterized by bloated line counts or redundant architectural abstractions.
* **Context Blindness:** While a patch may function in isolation, it frequently violates broader, repository-specific design patterns, naming conventions, or style guidelines.
* **Review Abandonment and Ghosting:** Because agents struggle to process multi-turn conversational feedback, they fail to address human critiques, prompting fatigued maintainers to close the stale branch.

**1. Diversity of weakness:**
