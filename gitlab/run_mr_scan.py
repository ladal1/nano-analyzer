#!/usr/bin/env python3
"""GitLab MR wrapper for nano-analyzer.

Features:
- Runs scans in CI, optionally on changed files only
- Maintains a single merge-request discussion for scanner output
- Updates discussion at start with a progress message
- Can skip rescans for already-processed commit SHA
"""

import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MARKER = "<!-- nano-analyzer:mr-report -->"
DEFAULT_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".java", ".py", ".go", ".rs", ".js", ".ts", ".rb",
    ".swift", ".m", ".mm", ".cs", ".php", ".pl", ".sh",
    ".x",
}


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _run(cmd, cwd=None, check=True):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return proc


def _normalize_path(path):
    return str(Path(path).as_posix())


def _resolve_diff_base():
    explicit = os.environ.get("NANO_GITLAB_CHANGED_BASE")
    if explicit:
        return explicit

    base_sha = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    if base_sha:
        return base_sha

    target_branch = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    if target_branch:
        _run(["git", "fetch", "origin", target_branch, "--depth", "100"], check=False)
        return f"origin/{target_branch}"

    return "HEAD~1"


def _changed_files(repo_root):
    base = _resolve_diff_base()
    head = os.environ.get("CI_COMMIT_SHA", "HEAD")
    diff_range = f"{base}...{head}"
    proc = _run(
        ["git", "diff", "--name-only", "--diff-filter=AMRT", diff_range],
        cwd=repo_root,
        check=False,
    )
    if proc.returncode != 0:
        # Fall back to two-dot in older/shallower clones.
        diff_range = f"{base}..{head}"
        proc = _run(
            ["git", "diff", "--name-only", "--diff-filter=AMRT", diff_range],
            cwd=repo_root,
            check=False,
        )

    paths = []
    for rel in proc.stdout.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        p = Path(repo_root, rel)
        if not p.is_file():
            continue
        if p.suffix.lower() in DEFAULT_EXTENSIONS:
            paths.append(rel)
    return sorted(set(paths))


def _scan_file(repo_root, relpath, output_dir):
    file_output = Path(output_dir, "files", relpath.replace("/", "__"))
    file_output.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(Path(repo_root, "scan.py")),
        relpath,
        "--output-dir",
        str(file_output),
    ]

    # Optional pass-through knobs.
    model = os.environ.get("NANO_GITLAB_MODEL")
    if model:
        cmd += ["--model", model]
    parallel = os.environ.get("NANO_GITLAB_PARALLEL")
    if parallel:
        cmd += ["--parallel", parallel]
    triage_rounds = os.environ.get("NANO_GITLAB_TRIAGE_ROUNDS")
    if triage_rounds:
        cmd += ["--triage-rounds", triage_rounds]

    _run(cmd, cwd=repo_root, check=True)

    summary_path = file_output / "summary.json"
    with open(summary_path, "r", encoding="utf-8") as fh:
        summary = json.load(fh)

    per_file = summary.get("per_file", [{}])[0]
    return {
        "path": relpath,
        "status": per_file.get("status", "unknown"),
        "elapsed": per_file.get("elapsed", 0),
        "severities": per_file.get("severities", {}),
    }


def _render_results(mode, commit_sha, scanned, skipped_reason=None):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        MARKER,
        "## Nano-analyzer report",
        "",
        f"Timestamp: {now}",
        f"Commit SHA: `{commit_sha}`",
        f"Mode: `{mode}`",
        "",
    ]

    if skipped_reason:
        lines += [f"Status: {skipped_reason}", ""]
        return "\n".join(lines)

    if not scanned:
        lines += ["No eligible files were scanned.", ""]
        return "\n".join(lines)

    lines += ["| File | Critical | High | Medium | Low | Status | Time (s) |", "|---|---:|---:|---:|---:|---|---:|"]
    for item in scanned:
        sev = item.get("severities", {})
        lines.append(
            "| {path} | {critical} | {high} | {medium} | {low} | {status} | {elapsed} |".format(
                path=_normalize_path(item["path"]),
                critical=sev.get("critical", 0),
                high=sev.get("high", 0),
                medium=sev.get("medium", 0),
                low=sev.get("low", 0),
                status=item.get("status", "unknown"),
                elapsed=item.get("elapsed", 0),
            )
        )

    lines += ["", "_Generated by nano-analyzer GitLab pipeline wrapper._"]
    return "\n".join(lines)


def _render_updating(commit_sha):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return "\n".join(
        [
            MARKER,
            "## Nano-analyzer report",
            "",
            f"Timestamp: {now}",
            f"Commit SHA: `{commit_sha}`",
            "",
            "This analysis is being updated...",
        ]
    )


def _extract_last_commit_sha(body):
    m = re.search(r"Commit SHA:\s*`([0-9a-fA-F]{7,40})`", body or "")
    return m.group(1) if m else None


class GitLabAPI:
    def __init__(self, api_url, project_id, mr_iid, token):
        self.api_url = api_url.rstrip("/")
        self.project_id = urllib.parse.quote(str(project_id), safe="")
        self.mr_iid = mr_iid
        self.token = token

    def _request(self, method, path, payload=None):
        url = f"{self.api_url}{path}"
        data = None
        headers = {"PRIVATE-TOKEN": self.token}
        if payload is not None:
            data = urllib.parse.urlencode(payload).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitLab API error {e.code} {method} {url}: {detail[:500]}")

    def list_discussions(self):
        path = (
            f"/projects/{self.project_id}/merge_requests/{self.mr_iid}/discussions"
            "?per_page=100"
        )
        data = self._request("GET", path)
        return data or []

    def create_discussion(self, body):
        path = f"/projects/{self.project_id}/merge_requests/{self.mr_iid}/discussions"
        return self._request("POST", path, payload={"body": body})

    def update_discussion_note(self, discussion_id, note_id, body):
        path = (
            f"/projects/{self.project_id}/merge_requests/{self.mr_iid}/discussions/"
            f"{discussion_id}/notes/{note_id}"
        )
        return self._request("PUT", path, payload={"body": body})

    def reopen_discussion(self, discussion_id):
        path = (
            f"/projects/{self.project_id}/merge_requests/{self.mr_iid}/discussions/"
            f"{discussion_id}"
        )
        return self._request("PUT", path, payload={"resolved": "false"})


def _find_existing_report_discussion(discussions):
    for disc in discussions:
        for note in disc.get("notes", []):
            body = note.get("body", "")
            if MARKER in body:
                return {
                    "discussion_id": disc.get("id"),
                    "note_id": note.get("id"),
                    "resolved": bool(disc.get("resolved")),
                    "body": body,
                }
    return None


def _upsert_report(gitlab, body, reopen_resolved):
    discussions = gitlab.list_discussions()
    existing = _find_existing_report_discussion(discussions)
    if not existing:
        created = gitlab.create_discussion(body)
        first_note = (created.get("notes") or [{}])[0]
        return {
            "discussion_id": created.get("id"),
            "note_id": first_note.get("id"),
            "resolved": bool(created.get("resolved")),
            "body": first_note.get("body", body),
        }

    if existing["resolved"] and reopen_resolved:
        try:
            gitlab.reopen_discussion(existing["discussion_id"])
        except Exception:
            # Keep pipeline non-fatal if project settings disallow resolve state changes.
            pass

    gitlab.update_discussion_note(existing["discussion_id"], existing["note_id"], body)
    existing["body"] = body
    existing["resolved"] = False
    return existing


def _append_local_report(output_dir, body):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "mr_comment.md", "w", encoding="utf-8") as fh:
        fh.write(body)


def main():
    repo_root = Path(os.environ.get("CI_PROJECT_DIR", os.getcwd())).resolve()
    output_dir = Path(os.environ.get("NANO_GITLAB_OUTPUT_DIR", repo_root / ".nano-analyzer" / "gitlab"))
    mode = os.environ.get("NANO_GITLAB_SCAN_MODE", "changed").strip().lower()
    if mode not in {"changed", "all"}:
        raise RuntimeError("NANO_GITLAB_SCAN_MODE must be 'changed' or 'all'")

    commit_sha = os.environ.get("CI_COMMIT_SHA", "")
    if not commit_sha:
        commit_sha = _run(["git", "rev-parse", "HEAD"], cwd=repo_root).stdout.strip()

    token = os.environ.get("NANO_GITLAB_API_TOKEN") or os.environ.get("GITLAB_API_TOKEN")
    api_url = os.environ.get("CI_API_V4_URL")
    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")

    gitlab = None
    existing = None
    if token and api_url and project_id and mr_iid:
        gitlab = GitLabAPI(api_url, project_id, mr_iid, token)
        discussions = gitlab.list_discussions()
        existing = _find_existing_report_discussion(discussions)

    enforce_once = _env_bool("NANO_GITLAB_ENFORCE_ONCE_PER_COMMIT", True)
    if enforce_once and existing:
        last_sha = _extract_last_commit_sha(existing.get("body", ""))
        if last_sha and last_sha == commit_sha:
            skipped = _render_results(mode, commit_sha, scanned=[], skipped_reason="Skipped: already analyzed for this commit SHA.")
            _append_local_report(output_dir, skipped)
            print("Skipping scan: commit already processed in MR comment.")
            return 0

    reopen_resolved = _env_bool("NANO_GITLAB_REOPEN_RESOLVED_THREAD", True)
    if gitlab:
        _upsert_report(gitlab, _render_updating(commit_sha), reopen_resolved)

    if mode == "all":
        target = os.environ.get("NANO_GITLAB_SCAN_TARGET", ".")
        full_output = output_dir / "full"
        full_output.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            str(repo_root / "scan.py"),
            target,
            "--output-dir",
            str(full_output),
        ]
        model = os.environ.get("NANO_GITLAB_MODEL")
        if model:
            cmd += ["--model", model]
        parallel = os.environ.get("NANO_GITLAB_PARALLEL")
        if parallel:
            cmd += ["--parallel", parallel]
        _run(cmd, cwd=repo_root, check=True)

        summary_json = full_output / "summary.json"
        scanned = []
        if summary_json.exists():
            with open(summary_json, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for item in data.get("per_file", []):
                scanned.append(
                    {
                        "path": item.get("file", "?"),
                        "status": item.get("status", "unknown"),
                        "elapsed": item.get("elapsed", 0),
                        "severities": item.get("severities", {}),
                    }
                )
    else:
        changed = _changed_files(repo_root)
        scanned = []
        for relpath in changed:
            scanned.append(_scan_file(repo_root, relpath, output_dir))

    final_body = _render_results(mode, commit_sha, scanned=scanned)
    _append_local_report(output_dir, final_body)

    if gitlab:
        _upsert_report(gitlab, final_body, reopen_resolved)

    print("nano-analyzer GitLab wrapper finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
