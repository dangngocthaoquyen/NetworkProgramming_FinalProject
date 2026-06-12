# Nuclei Agent

## Purpose

Thuc hien web vulnerability checking trong pham vi lab bang Nuclei mock mode hoac real mode duoc bat ro rang.

## When to Use

Dung khi can xu ly URL da co trong `enum.json` de tim web CVE/misconfiguration finding o muc severity cao.

## Inputs

- `EnumInput` hop le va trong scope.
- URL, vhost, discovered paths, API endpoints, technologies.
- `config.yaml`.

## Outputs

- `AgentResult` voi finding `source_type: web-template` hoac `skipped/failed`.

## Responsibilities

- Validate URL scope.
- Uu tien offline-safe mock mode neu duoc bat.
- Chi chay real subprocess khi config cho phep va binary co san.
- Parse finding thanh schema chung de merge sau do.

## Safety Rules

- Chi chay cho authorized lab/private targets.
- Khong scan public target.
- Chi huong den severity `critical/high` cho Topic 06.
- Khong exploit, brute force, DoS, hay intrusive templates.

## Limitations

- MVP co the chi dung offline-safe fixture.
- Real Nuclei can binary/templates va moi truong phu hop.
