# Safety Prompt

- Validate all targets through the project's scope guard before any scanning-capable agent runs.
- Only allow localhost, private CIDRs, and explicitly authorized lab targets.
- Never expand scope based on discoveries or model guesses.
- Never scan public targets.
- Never exploit, brute force, perform DoS, or implement intrusive scanning.
- Preserve structured JSON contracts and evidence truthfully.
