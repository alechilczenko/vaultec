# API Import — Scanner / script ingestion

Minimal guide for pushing assets, templates, and findings over REST (Nuclei, Nessus, Burp, custom scripts, etc.). Interactive schema explorer: Swagger UI at `/docs` when the server is running.

---

## 1. Required flow

```
POST /auth/token
GET  /workspace                         # empty → setup required
POST /workspace/setup                   # only if status === "empty"
POST /assets/import                     # or create; assets before findings
POST /templates/import                  # optional (global library)
POST /findings/import                   # max 100; all-or-nothing
```

Hard order: **Asset → Finding**. A finding with a missing `asset_name` fails. Templates live in the global library and can be imported with or without an active assessment.

Typical base URL: `http://localhost:8000`.

---

## 2. Auth

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=<ADMIN_SETUP_PASSWORD>" \
  | jq -r .access_token)
```

All other routes need `Authorization: Bearer $TOKEN`. JWT lasts ~8 hours; there is no refresh — call `POST /auth/token` again.

---

## 3. Active assessment

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/workspace
```

If `status` is `"empty"`:

```bash
curl -s -X POST http://localhost:8000/workspace/setup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"pentest-2026","client_name":"Acme"}'
```

If an assessment is already active, setup returns **409**. To start clean: `DELETE /admin/workspace/reset` → setup again (clears assets/findings/notes; keeps templates).

---

## 4. Scanner → API mapping

| Scanner concept | Field / endpoint |
| --- | --- |
| Host, IP, URL | Asset `name` + `type` (`IP` \| `URL` \| `Host`) → `POST /assets/import` |
| Known plugin / CVE / library template | Finding `definition_id` (numeric library id) |
| Finding without an internal id | Finding `title` + `severity` (**always** creates a new template; never reuses by title) |
| Request/response or proof | `evidence.packages[]` (`type`: `http` \| `general`) |
| Tool name | `discovered_by` (max 24) |

**Enums**

- Severity: `info` \| `low` \| `medium` \| `high` \| `critical`
- Finding status: `open` \| `remediated` \| `risk_accepted` \| `false_positive`
- Asset type: `IP` \| `URL` \| `Host`

**Limit:** max **100** items per import request.

---

## 5. `POST /assets/import`

**Body:** `{ "assets": [ { "name", "type", "notes?" } ] }`

- Duplicate names in the workspace are **skipped** (batch still succeeds).
- Typical response: `summary.added_count` / `skipped_count`, `details.added_assets` / `ignored_duplicates`.

```bash
curl -s -X POST http://localhost:8000/assets/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @assets.json
```

Minimal example:

```json
{
  "assets": [
    { "name": "10.0.4.50", "type": "IP" },
    { "name": "https://api.example.com", "type": "URL", "notes": "Auth API" }
  ]
}
```

---

## 6. `POST /templates/import` (optional)

**Body:** `{ "templates": [ { "id?", "title", "severity", "description", "recommendation", "category?", "tags?" } ] }`

- Existing `id` → **update**; missing `id` or unknown id → **insert**.
- `title` is **not** unique: omitting `id` always inserts a new row.

```bash
curl -s -X POST http://localhost:8000/templates/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @templates.json
```

---

## 7. `POST /findings/import`

**Body:** `{ "vulnerabilities": [ ... ] }` — max 100.

Each row needs `asset_name` and **one** of:

1. `definition_id` — links an existing template (missing id cancels the batch), or  
2. `title` + `severity` — creates a new library template.

Optional instance fields: `status` (default `open`), `notes`, `discovered_by`, `evidence`.

**All-or-nothing:** any invalid row → **400**, **zero** writes (including inline templates).

**200**

```json
{
  "message": "Import completed.",
  "summary": { "imported": 2, "failed": 0, "total": 2 },
  "details": { "errors": [] }
}
```

**400**

```json
{
  "detail": {
    "message": "Import cancelled",
    "errors": ["Row 1: …", "Row 3: …"]
  }
}
```

### Inline template example (typical scanner path)

```json
{
  "vulnerabilities": [
    {
      "title": "Missing security headers",
      "severity": "low",
      "category": "Misconfiguration",
      "description": "No Content-Security-Policy on the login page.",
      "recommendation": "Set CSP and related hardening headers.",
      "asset_name": "https://api.example.com",
      "status": "open",
      "discovered_by": "Nuclei",
      "notes": "Observed on login page; CSP header absent.",
      "evidence": {
        "packages": [
          {
            "type": "http",
            "items": [
              {
                "label": "Response headers",
                "content": "HTTP/1.1 200 OK\nServer: nginx\n..."
              }
            ]
          }
        ]
      }
    }
  ]
}
```

### `definition_id` example

```json
{
  "vulnerabilities": [
    {
      "definition_id": 101,
      "asset_name": "https://api.example.com",
      "discovered_by": "Burp Suite",
      "status": "open"
    }
  ]
}
```

```bash
curl -s -X POST http://localhost:8000/findings/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @findings.json
```

Uniqueness: one finding per `(definition_id, asset)` pair. Re-importing the same pair cancels the batch.

---

## 8. Common errors

| Situation | Code / symptom |
| --- | --- |
| Missing / expired token / inactive user | **401** |
| Workspace `empty` while calling assets/findings | **409** — run `POST /workspace/setup` |
| `asset_name` does not exist | **404** (create) or row in `detail.errors` (findings import) |
| `(definition_id, asset)` already exists | **400** / import cancelled |
| More than 100 items in the array | **422** |
| Findings import with one bad row | **400** `Import cancelled` — nothing written |
| Setup while assessment already active | **409** — reset first if needed |

---

## 9. Export / report (post-import)

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/findings/export -o findings.json

curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/findings/report -o findings-report.pdf
```

Also available: `GET /assets/export`, `GET /templates/export`.
