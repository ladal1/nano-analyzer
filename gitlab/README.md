# GitLab Pipeline Integration

This folder contains a ready-to-adapt GitLab CI integration for nano-analyzer.

## Files

- `.gitlab-ci.yml`: MR job template (serial execution + artifacts)
- `Dockerfile`: container with optional dependencies (`rg`, `csearch`, `cindex`)
- `run_mr_scan.py`: orchestration wrapper for changed-file scans + MR comment upsert

## 1) Build and publish the container

Build the image from `gitlab/Dockerfile` and publish it to your GitLab registry.

Example:

```bash
docker build -f gitlab/Dockerfile -t registry.gitlab.com/<group>/<project>/nano-analyzer:latest .
docker push registry.gitlab.com/<group>/<project>/nano-analyzer:latest
```

Then set `NANO_GITLAB_IMAGE` in CI variables (or in `gitlab/.gitlab-ci.yml`).

## 2) Enable the pipeline job

Option A: copy `gitlab/.gitlab-ci.yml` content into your root `.gitlab-ci.yml`.

Option B: include it from root `.gitlab-ci.yml`:

```yaml
include:
  - local: gitlab/.gitlab-ci.yml
```

## 3) Required CI variables

- `NANO_GITLAB_API_TOKEN` (or `GITLAB_API_TOKEN`): GitLab REST API token with access to MR discussions/notes

The wrapper also uses standard GitLab MR variables from CI (`CI_API_V4_URL`, `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, `CI_COMMIT_SHA`).

## 4) Behavior and configuration

- `NANO_GITLAB_SCAN_MODE`:
  - `changed` (default): scan only changed source files
  - `all`: run against `NANO_GITLAB_SCAN_TARGET` (default `.`)
- `NANO_GITLAB_CHANGED_BASE`: explicit base commit/branch for diff (optional)
- `NANO_GITLAB_ENFORCE_ONCE_PER_COMMIT`:
  - `true` (default): reads commit SHA stored in existing MR report comment and skips duplicate commit rescans
- `NANO_GITLAB_REOPEN_RESOLVED_THREAD`:
  - `true` (default): if existing report discussion is resolved, attempt to reopen before updating
- `NANO_GITLAB_RESOURCE_GROUP`:
  - serial lock key for the job; keep shared value to force one-at-a-time execution
- `NANO_GITLAB_OUTPUT_DIR`:
  - where wrapper stores generated markdown summaries (default `.nano-analyzer/gitlab`)

Optional pass-through analyzer tuning:

- `NANO_GITLAB_MODEL`
- `NANO_GITLAB_PARALLEL`
- `NANO_GITLAB_TRIAGE_ROUNDS`

## 5) MR comment lifecycle

The wrapper maintains a single MR discussion marked by an internal marker.

For each run:

1. Find existing nano-analyzer discussion (or create one)
2. Update immediately with: `This analysis is being updated...`
3. Reopen discussion when configured and applicable
4. Replace with final report table and UTC timestamp

The final report includes `Commit SHA: <sha>` and is used for once-per-commit deduplication.
