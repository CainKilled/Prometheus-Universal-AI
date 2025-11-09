# Prometheus A+ Standard (Tier‑1++)
This document codifies what “A+ quality” means for Prometheus Runtime artifacts.

## Non‑Negotiable Criteria
1. **Determinism / Safety**
   - Scripts must begin with `#!/usr/bin/env bash` and `set -euo pipefail`.
   - No interactive prompts; provide env vars and flags instead.
   - Idempotent on re‑runs: no duplicate work; safe re‑execution.

2. **Integrity / Immutability**
   - Compute and verify **SHA‑256** for every ingested artifact.
   - Generate immutable **.manifest** and executable **.test** companions per file.
   - Maintain **Codex‑Lock** JSON with exact path + hash and **drift_tolerance=0.0**.

3. **VaultTime / Ownership**
   - Every deliverable must have a **VaultTime** record and support HMAC signing via `VAULTTIME_KEY`.
   - Signatures must be reproducible (unsigned fallback is deterministic).

4. **Portability / Dependencies**
   - Auto‑detect common tools (`jq`, `sha256sum`/`shasum`, `unzip`) with graceful fallbacks (Python hashing).
   - Avoid platform‑specific flags unless gated.

5. **Logging / Auditability**
   - Clear start/stop messages, key paths, computed hashes.
   - Append an integrity entry into `MANIFEST.integrity.json` when present.

6. **Repo Integration**
   - Place incoming archives under `assets/incoming/<timestamp>`.
   - Expand under `assets/sources/<archive_name>` and set read‑only.
   - Invoke repo builder if available: `./forge_zip.sh` or `hal forge`.

7. **No Placeholders**
   - No TODO/FIXME or dead stubs. All functions must perform real work or be removed.

8. **Style / Lint**
   - Shell is POSIX‑friendly; passes `shellcheck` (where available).
   - Self‑documented with short usage blocks and clear error messages.

## Companion Files (Immutability Protocol)
For each primary file `X`:
- `X.manifest.json` — inputs, outputs, tools, checksum, generation time.
- `X.test` — executable test that validates hashes and basic behavior.

## Validation Gates
- `./ingest_archive.test.sh` must verify Codex hashes and refresh VaultTime signature.
- Any hash drift is a **hard fail**.
