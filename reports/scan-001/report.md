# Phase 3 Vulnerability Report: COURSE-LAB-001

## Executive Summary

The authorized Phase 3 scan produced 4 normalized findings.

## Scope

- Target label: authorized-lab
- Authorized hosts: 192.168.56.10, 192.168.56.11
- Public Internet scanning: blocked

## OS Inventory

### 192.168.56.10

- Name/version: Ubuntu 22.04
- Kernel: 5.15.0
- Build: N/A
- Architecture: x86_64
- Confidence: 92.00%
- Source: phase2-os-fingerprint

### 192.168.56.11

- Name/version: Windows 10 22H2
- Kernel: N/A
- Build: 19045
- Architecture: x86_64
- Confidence: 88.00%
- Source: phase2-os-fingerprint

## Findings by Severity

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 3 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

## Technical Details

### CVE-2099-1001: Mock Ubuntu kernel vulnerability candidate

- CVE ID: CVE-2099-1001
- Host: 192.168.56.10
- Port: N/A
- Severity: high
- CVSS: 8.4
- Confidence: 0.95
- Risk score: 79.80
- Source type: os
- Source agents: cve_lookup_agent
- Evidence: Offline mock DB matched OS fingerprint on 192.168.56.10: name=Ubuntu, version=22.04, kernel=5.15.0, build=unknown using exact match.

### CVE-2099-1002: Mock Windows 10 build vulnerability candidate

- CVE ID: CVE-2099-1002
- Host: 192.168.56.11
- Port: N/A
- Severity: high
- CVSS: 7.8
- Confidence: 0.95
- Risk score: 74.10
- Source type: os
- Source agents: cve_lookup_agent
- Evidence: Offline mock DB matched OS fingerprint on 192.168.56.11: name=Windows 10, version=22H2, kernel=unknown, build=19045 using exact match.

### CVE-2021-41773: Apache HTTP Server path traversal

- CVE ID: CVE-2021-41773
- Host: 192.168.56.10
- Port: 8080
- Severity: high
- CVSS: 7.5
- Confidence: 0.95
- Risk score: 71.25
- Source type: service
- Source agents: cve_lookup_agent
- Evidence: Offline mock DB matched Apache httpd 2.4.49 on 192.168.56.10:8080/tcp using exact match.

### CVE-2099-0001: Mock nginx old-version finding

- CVE ID: CVE-2099-0001
- Host: 192.168.56.10
- Port: 80
- Severity: medium
- CVSS: 8.1
- Confidence: 0.80
- Risk score: 64.80
- Source type: service
- Source agents: cve_lookup_agent
- Evidence: Offline mock DB matched nginx 1.18.0 on 192.168.56.10:80/tcp using range match.

## Remediation

- **CVE-2099-1001: Mock Ubuntu kernel vulnerability candidate:** Review Ubuntu security notices and apply the approved kernel update.
- **CVE-2099-1002: Mock Windows 10 build vulnerability candidate:** Review Microsoft security guidance and apply approved cumulative updates.
- **CVE-2021-41773: Apache HTTP Server path traversal:** Upgrade Apache HTTP Server to a supported patched release.
- **CVE-2099-0001: Mock nginx old-version finding:** Upgrade nginx to a supported release after compatibility testing.

## Appendix

### Agent Status

- `cve_lookup_agent`: success - Found 4 high-severity offline CVE matches.
- `nuclei_agent`: skipped - Nuclei is disabled in config.yaml.

### Methodology

Findings were deduplicated by host, port, CVE ID, and title. Risk scores were calculated from CVSS and confidence, with a capped bonus for Nuclei confirmation.
