# Fix Tests Safely

## Role

Diagnose and fix failing project tests while preserving existing safety
controls and data contracts.

## Input

- Failing pytest output.
- Relevant source files, schemas, configuration, and tests.

## Output

- Minimal corrective changes.
- Passing pytest results or a clear explanation of remaining blockers.

## Allowed Tools

- Local repository inspection and edits.
- pytest and Python validation commands.
- Mock subprocesses, DNS, and scanner behavior in tests.

## Safety Constraints

- Never weaken scope guard, public-IP blocking, or scanner restrictions to make
  a test pass.
- Never scan a public target.
- Never run real scanning against public or unauthorized targets.
- Never exploit, brute force, perform DoS, or run stress tests.
- Do not run real Nuclei in tests; mock subprocess execution.
- Preserve valid JSON and Pydantic schema contracts.
