# Attackbot Research Notes — Architecture Candidates & References

## 1. Core Planning Architecture

### GoalAct — ⭐ Best candidate so far
[arxiv.org/abs/2504.16563](https://arxiv.org/abs/2504.16563)
Similar in spirit to HIPLAN, but dynamically updates the global plan as execution progresses rather than committing to a static plan upfront.

### STRUCTUREDAGENT — extension to GoalAct
[arxiv.org/pdf/2603.05294](https://arxiv.org/pdf/2603.05294)
Can be added on top of GoalAct to maintain and explore multiple alternative attack branches simultaneously (rather than a single linear plan).

### GraphAgent — advisor layer alongside GoalAct
[arxiv.org/pdf/2310.16421](https://arxiv.org/pdf/2310.16421)
Can act as an "advisor" component to:
- Reduce false positives
- Prioritize attack surfaces
- Generate human-readable explanations
- Learn program-specific patterns incrementally

---

## 2. Skill Learning / Reuse

### Theory-Code2 — internal "skill learner" component
[arxiv.org/pdf/2602.00929](https://arxiv.org/pdf/2602.00929)
Can be embedded as an internal component to **store complex workflows**. When a previously-seen workflow recurs, Theory-Code2 can execute it directly instead of re-planning from scratch — saving planning overhead on repeated attack patterns.

---

## 3. Knowledge Base / Autonomous Suggestion

### SymAgent — internal findings traversal
[arxiv.org/pdf/2502.03283](https://arxiv.org/pdf/2502.03283)
Can autonomously traverse the internal database of past findings and suggest novel attacks/exploits based on known attack surfaces.

### Graphs Meet AI Agents (survey)
[arxiv.org/html/2506.18019v1](https://arxiv.org/html/2506.18019v1)
"Taxonomy, Progress, and Future Opportunities" — useful as a **system design reference** for Attackbot's overall graph-agent architecture.

---

## 4. Exploitation & Orchestration

### VulnBot — active exploitation
[arxiv.org/pdf/2501.13411](https://arxiv.org/pdf/2501.13411)
Used for actively exploiting identified vulnerabilities. *(Needs deeper investigation into exact mechanics.)*

### LLM-based Semi-Autonomous Penetration Testing Agents
[arxiv.org/pdf/2502.15506](https://arxiv.org/pdf/2502.15506)
Can be used as an orchestration layer to enhance strategy and command generation.

---

## 5. Reinforcement Learning for Agent Training

### Asynchronous Methods for Deep RL (A3C)
[arxiv.org/pdf/1602.01783](https://arxiv.org/pdf/1602.01783)
Foundational RL training method — usable for future agent training. No immediate/intermediate value right now.

### Evaluation of RL for Autonomous Penetration Testing (A3C, Q-learning, DQN)
[arxiv.org/pdf/2407.15656](https://arxiv.org/pdf/2407.15656)
Compares algorithms (A3C, Q-learning, DQN) to help identify the ideal algorithm for training Attackbot's agents efficiently.

---

## 6. Vulnerability & Attack Graph Generation

### Predicting Multi-Vulnerability Attack Chains from SBOM Graphs
[arxiv.org/pdf/2604.04977](https://arxiv.org/pdf/2604.04977)
Can be used to find vulnerabilities in a project's packages, libraries, and dependencies.

### CrystalBall — Retriever-Augmented LLMs for Attack Graph Generation
[arxiv.org/pdf/2408.05855](https://arxiv.org/pdf/2408.05855)
Methodology for generating attack graphs using retrieval-augmented LLMs.

### Cybersecurity Knowledge Graph (Springer, April 2023)
[link.springer.com/article/10.1007/s10115-023-01860-3](https://link.springer.com/article/10.1007/s10115-023-01860-3)
Can be used to chain known vulnerabilities together to surface new vulnerabilities/exploits.

### Visualizing Cyber Threats: Introduction to Attack Graphs (PuppyGraph)
[puppygraph.com/blog/attack-graph](https://www.puppygraph.com/blog/attack-graph)
Architecture/design pattern reference applicable to Attackbot.

### Network Modelling in Analysing Cyber-Related Graphs
[frontiersin.org — fcpxs.2025.1620260](https://www.frontiersin.org/journals/complex-systems/articles/10.3389/fcpxs.2025.1620260/full)
Calculates probability on an existing attack graph to identify which "chain-kill" is most likely to result in a successful exploit — lets Attackbot deprioritize low-probability chains and focus compute on high-probability ones.

---

## 7. Tools & Frameworks (no paper link)

- **NASim** — Network Attack Simulator
- **Metasploit Framework** — integration target
- **MITRE ATT&CK Framework** — reference taxonomy

---

## Summary: How These Fit Together

| Layer | Candidate(s) |
|---|---|
| Global planning | GoalAct (base), STRUCTUREDAGENT (multi-branch extension) |
| Advisory / scoring | GraphAgent |
| Skill memory / reuse | Theory-Code2 |
| Internal knowledge suggestion | SymAgent |
| Exploitation execution | VulnBot |
| Strategy/command orchestration | LLM-based Semi-Autonomous PenTest Agents |
| Attack graph construction | CrystalBall, Cybersecurity KG, SBOM-based chain prediction |
| Attack path prioritization | Network Modelling (probability-based chain-kill scoring) |
| Training (future) | A3C / RL comparison paper |
| Reference architecture | Graphs Meet AI Agents survey, PuppyGraph attack graph pattern |
| External integration | NASim, Metasploit, MITRE ATT&CK |