# Merge and Rank Prompt

After the agents finish, normalize findings into a final Phase 3 candidate list.

- Deduplicate according to the project's implemented keys.
- Preserve `source_agents`, `source_type`, evidence, confidence, and remediation.
- Rank by the implemented risk scoring logic.
- Do not claim strong cross-agent correlation if the code only performs limited deduplication.
