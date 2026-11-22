<div align="center">
  <img src=".github/banners/vaultec-banner.png" alt="Vaultec" width="220" />
  <br /><br />
  <p>
    <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />&nbsp;
    <img src="https://img.shields.io/badge/PostgreSQL-336791?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL" />&nbsp;
    <img src="https://img.shields.io/badge/Alpine.js-8BC0D0?style=flat-square&logo=alpinedotjs&logoColor=black" alt="Alpine.js" />&nbsp;
    <img src="https://img.shields.io/badge/License-AGPLv3-f43f5e?style=flat-square" alt="AGPLv3" />
  </p>
</div>

---

Vaultec is a lightweight web workspace for managing active security assessments from start to finish. It lets you inventory assets, reuse standardized vulnerability definitions, and track findings with evidence and notes—without the overhead of heavy enterprise platforms.

Built for single-engagement focus, it separates reusable vulnerability templates from project-specific data. Its API-first design makes it easy to ingest output from any scanner and generate PDF reports at any point.

![Findings workspace](.github/banners/01-findings.png)

## Core Concepts

```mermaid
flowchart LR
    subgraph Global ["Global Library (Persistent)"]
        T[Vulnerability Templates]
    end

    subgraph Workspace ["Active Assessment Workspace"]
        A[Assets / Scope] --> F[Findings]
        T -.->|relink / instantiate| F
        F --> E[Evidence<br/>HTTP · General]
        F --> S[Status<br/>open · remediated<br/>risk accepted · false positive]
    end

    F ==>|GET /findings/report| R[Findings PDF]

    style Global fill:#18181b,stroke:#3f3f46,color:#f4f4f5
    style Workspace fill:#18181b,stroke:#e11d48,color:#f4f4f5
    style F fill:#27272a,stroke:#e11d48,color:#ffffff
    style R fill:#27272a,stroke:#10b981,color:#ffffff
```

* **Global Templates vs. Findings:** Vulnerability definitions (descriptions, severity, remediation guidance) live globally across engagements. Findings are concrete instances tied to a specific asset, holding status, technical notes, and proof of exploitation.
* **Library Mode:** Manage, import, and export your vulnerability template library even when no assessment workspace is active.
* **Single-Workspace Focus:** Designed around one active engagement at a time to eliminate context switching. Resetting the workspace clears assessment data while preserving your global template library.
* **Scanner-Agnostic Ingestion:** Feed findings from any external vulnerability scanner or custom script via atomic bulk JSON imports (`POST /findings/import`) — all-or-nothing validation ensures partial or malformed batches never pollute the workspace.
* **Findings PDF Report:** Download an A4 PDF grouped by vulnerability definition (`GET /findings/report`) with workspace metadata, at any stage of the engagement. Rendered via headless Chrome/Chromium on the server.
* **Zero-Build UI:** Served directly by FastAPI using Jinja2 templates and Alpine.js (`app/ui/`), requiring no Node.js runtime or bundler.

## Installation

**Requirements:** Python 3.11+, Docker (or PostgreSQL 16), and Google Chrome or Chromium (needed for `GET /findings/report` PDF rendering; without it the API returns 503).

```bash
git clone https://github.com/alechilczenko/vaultec.git
cd vaultec
```

### Database

```bash
docker compose up -d
```

Defaults: user `admin`, password `password123`, database `app`, port `5432`. Override with `DB_USER`, `DB_PASSWORD`, and `DB_NAME` if needed.

### Install

```bash
cd app
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure

Create `app/.env`:

```env
SECRET_KEY=                 # openssl rand -hex 32  (min 32 chars)
ADMIN_SETUP_PASSWORD=       # 12+ chars; upper, lower, digit, symbol
DATABASE_URL=postgresql://admin:password123@localhost:5432/app
```

On first boot the app creates tables and ensures a user `admin` with `ADMIN_SETUP_PASSWORD`.

### Start

```bash
cd app
source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open http://localhost:8000/ and sign in as `admin` with `ADMIN_SETUP_PASSWORD`.

## API Automation Example

Every action in the UI is backed by the REST API. You can parse output from any scanner (Nuclei, Nessus, Burp, Nmap, or custom scripts) into the bulk import schema and push it directly into the active workspace. Full flow (auth, setup, assets, findings): [`docs/API_IMPORT.md`](docs/API_IMPORT.md). Swagger UI at `/docs` when the server is running.

```bash
# Ingest parsed scanner findings atomically (all-or-nothing)
curl -s -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d @findings.json \
  http://localhost:8000/findings/import
```

## Gallery

![Finding detail with HTTP evidence](.github/banners/04-finding-detail.png)

![New template](.github/banners/10-new-template.png)

## Contributing

Bug reports, architectural feedback, and pull requests are welcome. Please open an issue first to discuss significant changes.

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE).

Copyright (C) 2026 Alejandro Chilczenko