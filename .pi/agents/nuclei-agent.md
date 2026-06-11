# Nuclei Agent

## Role

Optionally run a safety-constrained Nuclei subprocess against authorized,
validated URLs.

## Input

- A validated `EnumInput` object.
- `config.yaml` with `enable_nuclei` and safety scope settings.
- Validated base URLs plus optional vhost, technology, discovered-path, and API
  endpoint metadata supplied by earlier phases.

## Output

- A valid `AgentResult` with status `success`, `partial`, `failed`, or
  `skipped`.
- Parsed findings that conform to the shared Pydantic schema.

## Allowed Tools

- `ScopeGuard`.
- `shutil.which`.
- Controlled `asyncio.create_subprocess_exec`.
- Nuclei JSONL parsing.

## Safety Constraints

- Default to skipped when `enable_nuclei: false`.
- An explicitly enabled offline mock mode may read only local safe fixtures;
  it must not launch a subprocess or contact a target.
- Vhosts and paths are context only and must not expand authorized scope.
- Never run against a public target or an URL that has not passed scope guard.
- Only allow severity `critical`, `high`, and `medium`.
- Exclude templates tagged `dos`, `brute-force`, or `intrusive`.
- Never exploit, brute force, perform DoS, or run stress tests.
- Handle missing binaries, errors, and timeouts without crashing the pipeline.
- Produce valid structured JSON whenever JSON output is required.
