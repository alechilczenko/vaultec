<p align="center">
  <img src=".github/banners/logo.png" alt="APP mark" width="96" height="96" />
</p>

<h1 align="center">APP</h1>

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/PostgreSQL-336791?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Alpine.js-8BC0D0?style=flat-square&logo=alpinedotjs&logoColor=black" alt="Alpine.js" />
  <img src="https://img.shields.io/badge/License-AGPLv3-f43f5e?style=flat-square" alt="AGPLv3" />
</p>

**APP** is a web workspace for active security assessments. It aims to keep an engagement coherent from start to finish: inventory the assets in scope, reuse standardized vulnerability definitions, and track findings from discovery through remediation — with evidence and notes attached.

Built for single-engagement focus without the overhead of heavy enterprise platforms, it separates reusable vulnerability knowledge from engagement-specific evidence. Its API-first design lets you ingest output from any vulnerability scanner and generate a findings PDF report at any point in the assessment.

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
* **Zero-Build UI:** Served directly by FastAPI using Jinja2 templates and Alpine.js (`backend/ui/`), requiring no Node.js runtime or bundler.

## Installation

**Requirements:** Python 3.11+, Docker (or PostgreSQL 16), and Google Chrome or Chromium (needed for `GET /findings/report` PDF rendering; without it the API returns 503).

```bash
git clone https://github.com/alechilczenko/APP.git
cd APP
```

### Database

```bash
docker compose up -d
```

Defaults: user `admin`, password `password123`, database `app`, port `5432`. Override with `DB_USER`, `DB_PASSWORD`, and `DB_NAME` if needed.

### Install

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure

Create `backend/.env`:

```env
SECRET_KEY=                 # openssl rand -hex 32  (min 32 chars)
ADMIN_SETUP_PASSWORD=       # 12+ chars; upper, lower, digit, symbol
DATABASE_URL=postgresql://admin:password123@localhost:5432/app
```

On first boot the app creates tables and ensures a user `admin` with `ADMIN_SETUP_PASSWORD`.

### Start

```bash
cd backend
source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open http://localhost:8000/ and sign in as `admin` with `ADMIN_SETUP_PASSWORD`.

| URL | |
| --- | --- |
| http://localhost:8000/ | Login |
| http://localhost:8000/workspace/findings | Findings |
| http://localhost:8000/workspace/templates | Templates |
| http://localhost:8000/workspace/assets | Assets |
| http://localhost:8000/docs | OpenAPI (Swagger) |

### Model

Create assets → instantiate findings from templates → attach evidence → move status (`open` → `remediated`, or close as `risk accepted` / `false positive`). PATCH updates the instance, not the global definition.

### Tests

```bash
cd backend
source .venv/bin/activate
python -m pytest
```

## API Automation Example

Every action in the UI is backed by the REST API. You can parse output from any scanner (Nuclei, Nessus, Burp, Nmap, or custom scripts) into the bulk import schema and push it directly into the active workspace:

```bash
# Ingest parsed scanner findings atomically (all-or-nothing)
curl -s -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d @parsed-scanner-output.json \
  http://localhost:8000/findings/import

# Download findings PDF report
curl -s -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8000/findings/report -o findings-report.pdf

# Export full template library (JSON)
curl -s -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8000/templates/export -o templates-library.json
```

## Gallery

Workspace lists:

![Assets inventory](.github/banners/02-assets.png)

![Template library](.github/banners/03-templates.png)

Finding workflow:

![Finding detail with HTTP evidence](.github/banners/04-finding-detail.png)

![Edit finding](.github/banners/05-finding-edit.png)

![New finding (template picker)](.github/banners/06-new-finding.png)

Library & scope:

![Template detail](.github/banners/07-template-detail.png)

![New template](.github/banners/10-new-template.png)

![Asset detail](.github/banners/08-asset-detail.png)

![Scratchpad notes](.github/banners/09-notes.png)

## Contributing

Bug reports, architectural feedback, and pull requests are welcome. Please open an issue first to discuss significant changes.

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE).

Copyright (C) 2026 Alejandro Chilczenko