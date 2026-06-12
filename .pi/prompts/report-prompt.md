# Report Prompt

Generate the final Phase 3 report from validated findings and enumeration context.

- Treat `enum.json` as pre-collected input, not as something produced by this run.
- Do not claim Phase 0, Phase 1, or Phase 2 execution.
- Do not claim real scanning beyond what the implementation actually performed.
- Preserve authorized-scope language and limitations such as offline-safe/mock-backed paths when applicable.
