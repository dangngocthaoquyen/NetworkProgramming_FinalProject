# Topic 06 - Phase 3 Vulnerability Scanning

This repository implements Topic 06: the Phase 3 vulnerability scanning stage of a pentesting workflow.

The runtime pipeline starts from a pre-collected `enum.json` shared artifact, runs `cve_lookup_agent` and `nuclei_agent` in parallel, merges and ranks the results, and writes `vuln.json` plus a Markdown report.

## Scope

- This project starts from `enum.json`.
- Enumeration and reconnaissance are outside the runtime scope.
- Exploitation, post-exploitation, brute force, and DoS are outside scope.
- Only authorized lab targets, localhost, and private networks are allowed.
- The pipeline must not expand scope beyond the input artifact and configured safety rules.

## Architecture

```text
enum.json
  -> scope validation
  -> cve_lookup_agent + nuclei_agent in parallel
  -> merge / deduplicate / rank
  -> vuln.json + report.md
```

Runtime flow in the codebase:

- `run_phase3.py` loads the enum artifact and calls the orchestrator.
- `app/orchestrator.py` validates scope, launches both agents with `asyncio.gather`, merges results, and writes outputs.
- `app/merge/` handles deduplication and scoring.
- `app/reports/markdown_report.py` renders `report.md`.

## Agents

### `cve_lookup_agent`

- Input: enumerated service, product, version, and CPE data from `enum.json`
- Source: NVD/NIST live API or local NVD cache as the primary source, with OSV as a supplementary package-intelligence source inside the same agent
- Filter: `CVSS >= 7.0`
- Output: candidate CVE findings for later ranking and manual triage
- Matching notes:
  - Exact CPE matches are preferred.
  - Range-based CPE matches are disabled by default unless enabled in config.
  - OSV lookups only run when an explicit package/ecosystem mapping is configured.
  - CPE/version-based findings are candidate matches and still require manual validation.

Implementation note:

- `cve_lookup_agent` remains one agent. OSV is not a third runtime agent.
- NVD is still the best fit for CPE and service-version matching from Nmap-style input.
- OSV is better suited to package, SBOM, and dependency ecosystem matching, so this project only uses it when package mapping is explicit and trustworthy.
- With service banners and CPE-only input such as the Metasploitable3 sample, OSV may legitimately produce zero findings.

### `nuclei_agent`

- Input: in-scope web URLs derived from the enum artifact
- Modes: `mock`, `cli`, `auto`
- CLI mode uses a local Nuclei binary
- Severity filter: `critical`, `high`
- Safety filter: excludes `dos`, `brute-force`, and `intrusive` template tags
- Output: candidate web-template findings that are merged with CVE lookup results

Current project config:

- `config.yaml` currently sets `nuclei.mode: "cli"` and `nuclei.use_mock_fallback: true`
- If the binary is unavailable, the agent can fall back to offline mock findings

## Parallelism

`cve_lookup_agent` and `nuclei_agent` are independent tasks, so the orchestrator runs them concurrently with `asyncio.gather`. The results are then merged asynchronously, deduplicated, and ranked. This shortens total runtime compared with running both scanning tasks serially.

## Input And Output

Sample input:

- `data/samples/enum_metasploitable3_ub1404.json`

Expected runtime outputs:

- `reports/<run-name>/vuln.json`
- `reports/<run-name>/report.md`
- `logs/<run-name>.log`
- `logs/pipeline.log`
- `triage/vuln.json`
- `triage/cve_candidates.json`
- `triage/nuclei_results.json`

Important boundary:

- Runtime artifacts must stay outside `.pi/`.
- `.pi/chain/` is documentation for orchestration only and must not store runtime results.

## `.pi/` Structure

- `.pi/agents/`: agent descriptions for the project workflow
- `.pi/prompts/`: prompt assets and safety/report guidance
- `.pi/skills/`: reusable project-specific skills and references
- `.pi/extensions/`: extension notes and support material
- `.pi/chain/`: orchestration documentation only, not runtime artifact storage

## Repository Layout

```text
app/
  agents/       Runtime scanning agents
  merge/        Deduplicate and scoring logic
  normalizers/  Enum payload enrichment and normalization
  reports/      Markdown report generation
  schemas/      Pydantic contracts for input and output
  tools/        Scope guard and NVD client
data/
  samples/      Authorized sample enum inputs
logs/           Runtime logs
reports/        Per-run report outputs
tests/          Pytest coverage
triage/         Latest machine-readable artifacts
```

## Configuration

Important settings in `config.yaml`:

### `cve_lookup`

- `cve_lookup.source`
  - `mock`: offline fixture data only
  - `nvd_live`: query NVD/NIST live API
  - `auto`: prefer cache or live lookup when available, otherwise fall back safely
- `cve_lookup.min_cvss`
  - Minimum accepted CVSS score. Topic 06 expects `>= 7.0`.
- `cve_lookup.nvd.cache_dir`
  - Directory for cached NVD responses
- `cve_lookup.nvd.use_cache`
  - Enables cached NVD reuse
- `cve_lookup.nvd.timeout_seconds`
  - Timeout for NVD HTTP requests
- `cve_lookup.nvd.allow_range_matches`
  - Controls whether CPE version-range matches are accepted
- `cve_lookup.osv.enabled`
  - Enables supplementary OSV lookups inside `cve_lookup_agent`
- `cve_lookup.osv.base_url`
  - OSV API base URL, default `https://api.osv.dev/v1`
- `cve_lookup.osv.cache_dir`
  - Directory for cached OSV responses
- `cve_lookup.osv.timeout_seconds`
  - Timeout for OSV HTTP requests
- `cve_lookup.osv.max_batch_size`
  - Maximum number of explicit package-version queries per OSV batch request
- `cve_lookup.osv.enabled_for_package_ecosystems`
  - Allow-list of ecosystems that the agent may query when a matching package mapping exists
- `cve_lookup.osv.package_mappings`
  - Explicit service-to-package mappings. Leave empty unless you have a trustworthy package/ecosystem mapping. This project does not infer package names from generic service banners.

### `nuclei`

- `nuclei.mode`
  - `mock`, `cli`, or `auto`
- `nuclei.binary`
  - Path or executable name for the local Nuclei binary
- `nuclei.severity`
  - Allowed result severities, expected here as `critical` and `high`
- `nuclei.timeout_seconds`
  - Timeout for one CLI run
- `nuclei.use_mock_fallback`
  - Allows safe offline fallback when CLI mode is unavailable

### `scanner`

- `scanner.max_concurrency`
  - Concurrency limit used by the orchestrator semaphore

### `safety`

- `safety.allowed_cidrs`
  - Explicitly allowed networks
- `safety.block_public_ip`
  - Blocks public IP scanning when `true`

## NVD Setup

- The NVD API key is read from `NVD_API_KEY`.
- Do not commit API keys.
- `.env` should stay ignored by Git.
- If local NVD cache files exist in `data/cache/nvd/`, they support reproducible demo runs and reduce live API dependency.

Example `.env`:

```dotenv
NVD_API_KEY=your_nvd_api_key_here
NUCLEI_BINARY=E:\go\bin\nuclei.exe
```

## Nuclei CLI Setup On Windows

Install with Go:

```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

If `C:` is low on space, you can move Go paths to `E:` before installation:

```powershell
$env:GOPATH="E:\go"
$env:GOBIN="E:\go\bin"
$env:GOCACHE="E:\go-cache"
$env:GOTMPDIR="E:\go-tmp"
$env:TEMP="E:\Temp"
$env:TMP="E:\Temp"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Verify the binary:

```powershell
E:\go\bin\nuclei.exe -version
```

Update templates:

```powershell
nuclei -update-templates
```

Short form:

```powershell
nuclei -ut
```

## Demo Commands

Run tests:

```powershell
python -m pytest
```

Run the default demo:

```powershell
python run_phase3.py --enum data/samples/enum_metasploitable3_ub1404.json --out reports/metasploitable3-demo
```

Run the CLI demo:

```powershell
python run_phase3.py --enum data/samples/enum_metasploitable3_ub1404.json --out reports/metasploitable3-cli-demo
```

Note:

- The CLI demo is meaningful when `nuclei.mode` is set to `cli` or `auto` and a local Nuclei binary is available.
- With `use_mock_fallback: true`, the run can still complete safely using offline mock findings.

## Result Interpretation

- CVE findings are candidates based on service, version, and CPE matching against NVD or cached data.
- OSV findings are supplementary package-level candidates, not CPE-exact confirmations.
- If an OSV record aliases an NVD CVE, the project deduplicates them into one finding and preserves both intel sources.
- Candidate findings still require manual validation before claiming real vulnerability exposure.
- Nuclei CLI returning zero `critical` or `high` findings with exit code `0` is still a successful scan.
- Mock findings are offline fixtures for reproducible demos and tests.
- This project does not confirm exploitation and must not be presented as exploitation proof.

## Safety Rules

- Authorized lab and private targets only
- No public Internet scanning
- No exploitation
- No brute force
- No DoS or stress testing
- No intrusive template execution
- No automatic scope expansion
- Secrets, caches, and runtime outputs should not be committed

## Git Ignore Expectations

The repository should keep these ignored:

- `.env`
- `.env.*`
- `data/cache/nvd/`
- `data/cache/osv/`
- `reports/*` except keepers such as `README.md` or `.gitkeep`
- `logs/*` except keepers such as `README.md` or `.gitkeep`
- `triage/*` except keepers such as `README.md` or `.gitkeep`
- Python cache files
- pytest cache

## Verification

Minimum verification:

```powershell
python -m pytest
```

Optional demo verification:

```powershell
python run_phase3.py --enum data/samples/enum_metasploitable3_ub1404.json --out reports/metasploitable3-demo
```
