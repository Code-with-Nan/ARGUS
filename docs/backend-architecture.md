# ARGUS Backend Integration Notes

This document describes a proposed FastAPI and PostgreSQL boundary. It is an integration design only: no API, database connection, CRUD operation, or scanner is implemented by this frontend.

## Service boundary

- Next.js calls FastAPI through `NEXT_PUBLIC_API_BASE_URL`; browser code must never connect to PostgreSQL.
- Keep request/response types and transport concerns in `src/lib/api.ts`. Add endpoint-specific functions only when the corresponding FastAPI contract exists.
- Keep database credentials in backend environment variables or a deployment secret manager. Never expose them through `NEXT_PUBLIC_*` variables, source control, or client bundles.
- Configure SQLAlchemy sessions per request, use Alembic for schema changes, and validate inbound and outbound payloads with Pydantic.
- Roll back failed transactions, log a correlation ID and safe error category, and return a non-sensitive error response. Do not return SQL, credentials, secret values, or raw exception traces to clients.

## Proposed relational model

Use UUID primary keys and UTC `created_at` / `updated_at` timestamps. Add foreign-key indexes for the relationships below, and use database-level constraints for unique identifiers and valid status values.

| Table | Key fields and relationships |
| --- | --- |
| `users` | `id`, normalized unique `email`, `display_name`, optional external identity subject, `created_at`, `updated_at`. If password auth is introduced, store only a modern password hash, never the password. |
| `projects` | `id`, `owner_user_id` to `users`, `name`, `created_at`, `updated_at`, optional `archived_at`. A user owns many projects. |
| `scans` | `id`, `project_id` to `projects`, `initiated_by_user_id` to `users`, constrained `status`, scanner/version manifest, archive digest, start/finish timestamps, safe failure code. A project has many immutable scan runs. |
| `vulnerabilities` | `id`, `scan_id` to `scans`, scanner, rule ID, category, severity, title, description, relative file path, line range, stable deduplication fingerprint, `created_at`. A scan has many findings. Avoid retaining source excerpts by default. |
| `remediation_suggestions` | `id`, `vulnerability_id` to `vulnerabilities`, recommendation text, optional proposed patch, provenance/model metadata, `created_at`. Treat generated content as untrusted input and require developer review. |
| `remediation_approvals` | `id`, `suggestion_id` to `remediation_suggestions`, `reviewer_user_id` to `users`, constrained decision (`approved` / `rejected`), optional comment, `decided_at`. Preserve approvals as append-only audit events. |
| `verification_results` | `id`, original `vulnerability_id`, `baseline_scan_id`, `followup_scan_id`, constrained verification status, `resolved` nullable until comparison completes, new-finding/regression references, `verified_at`. Keep each rescan comparison as history rather than overwriting the original finding. |

Suggested constraints: unique `(project_id, archive_digest, scanner_manifest)` only if scan deduplication is desired; unique `(scan_id, scanner, rule_id, fingerprint)` for finding identity; checks for enumerated statuses/severities; and foreign keys that prevent deleting audit history accidentally. Use explicit retention policies for projects and scan history.

## Uploads and secret findings

- Do not store source archives in PostgreSQL. Store archives, if retention is required, in private object storage with short-lived scoped access, encryption, malware/archive validation, size limits, and lifecycle deletion. Otherwise use isolated temporary storage and delete it after scanning.
- Never execute uploaded project code. Validate archive paths, reject traversal and unsafe entry types, enforce decompression limits, and scan in an isolated worker.
- Gitleaks results must not persist secret plaintext. Store a redacted value, rule and location, and—only when deduplication is needed—a keyed digest. Restrict access to sensitive finding metadata and avoid putting it in logs or analytics.

## Configuration

Backend-only configuration should include `DATABASE_URL` and any object-storage or signing credentials through the runtime secret manager. Keep a blank local template for variable names only; never commit populated credentials. The frontend's `.env.example` contains only the public API base URL.