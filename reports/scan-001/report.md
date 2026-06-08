# Phase 3 Vulnerability Report: COURSE-LAB-001

## Executive Summary

The authorized Phase 3 scan produced 1 normalized findings.

## Scope

- Target label: authorized-lab
- Authorized hosts: 192.168.56.10
- Public Internet scanning: blocked

## Findings by Severity

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

## Technical Details

### CVE-2099-0001: Mock nginx old-version finding

- CVE ID: CVE-2099-0001
- Host: 192.168.56.10
- Port: 80
- Severity: medium
- CVSS: 8.1
- Confidence: 0.80
- Risk score: 64.80
- Source agents: cve_lookup_agent
- Evidence: Offline mock DB matched nginx 1.18.0 on 192.168.56.10:80/tcp using range match.

## Remediation

- **CVE-2099-0001: Mock nginx old-version finding:** Upgrade nginx to a supported release after compatibility testing.

## Appendix

### Agent Status

- `cve_lookup_agent`: success - Found 1 high-severity local CVE matches.
- `nuclei_agent`: skipped - Nuclei is disabled in config.yaml.

### Methodology

Findings were deduplicated by host, port, CVE ID, and title. Risk scores were calculated from CVSS and confidence, with a capped bonus for Nuclei confirmation.
