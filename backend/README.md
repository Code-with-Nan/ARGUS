# ARGUS Backend

FastAPI service for source archive scanning, scan history, findings, developer-approved remediations, follow-up verification, and PDF reports.

## Setup

Use Python 3.12 or newer and PostgreSQL. Create the database named in `DATABASE_URL`, then configure the environment:

```sh
cp .env.example .env  # only when .env does not already exist; otherwise merge the settings
```

Set `DATABASE_URL` to the PostgreSQL instance and set a strong `API_TOKEN` before exposing the service. Install the backend requirements and start the API from this directory:

```sh
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The API creates missing SQLAlchemy tables at startup. Existing `scans` and `findings` tables are not altered; additive tables store scanner metadata, enriched finding fields, remediation records, and verification results. Existing scans remain readable, but scans created before persistent working copies were introduced cannot be rescanned or remediated through this API.

## Configuration

`.env.example` documents the supported settings. `CORS_ORIGINS` is a comma-separated allowlist and defaults to `http://localhost:3000`. Set `API_TOKEN` to require `X-API-Key` on upload, rescan, remediation creation, approval/rejection, and application requests. Keep it unset only for isolated local development.

The default workspace is `.argus/workspaces` under the backend directory. It contains uploaded source copies so later remediation and rescanning can operate on the same files. Treat this directory as sensitive, restrict access, and define an operational retention/cleanup policy. The upload defaults are 10 MiB compressed, 50 MiB extracted, 500 ZIP entries, and a 100:1 maximum compression ratio.

AI explanations default to a deterministic fallback. To use an OpenAI-compatible provider, configure `AI_PROVIDER=openai-compatible`, `AI_API_URL`, `AI_API_KEY`, and `AI_MODEL`. Only finding metadata is sent by default; source snippets are included only when `AI_INCLUDE_CODE=true`. Provider failures fall back to a clearly labelled deterministic explanation. No provider credentials are required for the fallback.

## Scanners

Bandit is installed with the backend requirements and runs for Python projects. Semgrep, Gitleaks, `pip-audit`, and npm audit are independent adapters and report `unavailable`, `skipped`, `failed`, or `completed` per scanner. Install the optional tools on the backend host to enable them:

```sh
pip install semgrep pip-audit
brew install gitleaks
```

npm audit requires Node.js/npm plus both `package.json` and `package-lock.json`; it uses the public npm registry and runs with lifecycle scripts disabled. The pip-audit adapter currently accepts pinned `name==version` requirements only and does not follow dependency links or install directives. Semgrep uses its `p/default` ruleset, which may require registry access. A scan is marked `partial` when any applicable scanner is unavailable or fails, and `failed` when no applicable scanner completes. Review `scanner_results` rather than treating missing coverage as a clean result.

Scanner subprocesses use fixed argument arrays (never a shell), a minimal environment, per-process timeouts, process-group termination, and a 10 MiB combined output cap. npm audit is run on staged manifest copies with scripts disabled and registry/config overrides; pip-audit is given only a staged, validated requirements file. Scanners are not an OS-level sandbox. Run ARGUS in a restricted worker/container with constrained network and filesystem access when processing untrusted archives.

## API

Interactive API documentation is available at `/docs` while the service is running.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/scans/upload` | Validate, persist, and scan a ZIP project |
| `GET` | `/api/v1/scans?page=1&page_size=20` | Paginated scan history |
| `GET` | `/api/v1/scans/{scan_id}` | Scan details, findings, scanner coverage, and remediation history |
| `POST` | `/api/v1/scans/{scan_id}/rescan` | Rescan the stored working copy |
| `POST` | `/api/v1/scans/{scan_id}/findings/{finding_id}/explanation` | Generate and persist an explanation |
| `POST` | `/api/v1/scans/{scan_id}/findings/{finding_id}/remediations` | Create a pending suggestion; optional `patch` is a developer-supplied unified diff |
| `POST` | `/api/v1/scans/remediations/{id}/approve` | Explicitly approve a pending remediation |
| `POST` | `/api/v1/scans/remediations/{id}/reject` | Reject a pending remediation |
| `POST` | `/api/v1/scans/remediations/{id}/apply` | Apply an approved patch and perform a follow-up scan |
| `GET` | `/api/v1/scans/{scan_id}/report.pdf` | Download a PDF report |

When `API_TOKEN` is configured, send `X-API-Key: <token>` on protected requests. Approval requests require `{"approved_by":"reviewer"}`; this label is recorded for audit purposes, while actual caller authentication is provided by the configured API token or an upstream identity-aware gateway.

Remediation patches can update existing regular files inside the managed working copy only. Absolute paths, traversal, symlinks, file additions/deletions/renames, mismatched context, and patches over 100 KiB are rejected. A suggested action is not automatically applied. Applying a patch always creates a new scan. Verification is `verified` only when the original finding's scanner completed on the follow-up scan and the matching rule/file finding is absent; otherwise the result is `unresolved` or `inconclusive`. No verification claim is made without that follow-up result.

## Tests

Tests use an isolated in-memory SQLite database and do not connect to the configured PostgreSQL instance:

```sh
python -m pytest -q
```

The suite covers ZIP traversal defense, scanner results on the vulnerable sample, scan history/details, fallback explanations, PDF output, approval gating, strict patch behavior, and a real Bandit upload-fix-follow-up scan.