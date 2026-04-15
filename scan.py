#!/usr/bin/env python3
# Copyright (c) 2026 Aisle Inc.
# SPDX-License-Identifier: Apache-2.0
"""
nano-analyzer: Minimal zero-day vulnerability scanner using LLMs.

Two-stage pipeline:
  1. A cheap model generates security context about the file
  2. The scanner model uses that context to find vulnerabilities

Usage:
  nano-analyzer ./path/to/folder          # scan all source files recursively
  nano-analyzer ./path/to/file.c          # scan a single file
  nano-analyzer ./src --parallel 30       # control concurrency
  nano-analyzer ./src --model gpt-5.4     # use a different scanner model
"""

import argparse
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

VERSION = "0.1"

DEFAULT_MODEL = "gpt-5.4-nano"
DEFAULT_PARALLEL = 50
DEFAULT_MAX_CHARS = 200_000
DEFAULT_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".java", ".py", ".go", ".rs", ".js", ".ts", ".rb",
    ".swift", ".m", ".mm", ".cs", ".php", ".pl", ".sh",
    ".x",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
    "clean": "🟢",
}

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

DEFAULT_SYSTEM_PROMPT = """\
You are a security researcher hunting for zero-day vulnerabilities. \
Analyze the code step by step, tracing how untrusted data flows into \
each function. For every function, ask yourself:

1. Can any parameter be NULL, too large, negative, or otherwise \
   invalid when this function is called with malformed input?
2. Are there copies into fixed-size buffers without size validation?
3. Can integer arithmetic overflow, wrap, or produce negative values \
   that are then used as sizes or indices?
4. Are tagged unions / variant types accessed without verifying the \
   type discriminator first?
5. Are return values from fallible operations checked before use?

Focus on bugs that an external attacker can trigger through untrusted \
input. Deprioritize static helpers with safe call sites, allocation \
wrappers, platform-specific dead code, and theoretical issues.

After your analysis, output a JSON array of findings. Each finding \
must have severity, title, function, and description. Output ONLY \
the JSON array at the end — your reasoning goes before it.\
"""

FEWSHOT_EXAMPLE_USER = """\
Analyze the following source file for zero-day vulnerabilities.

File: example/net/parser.c

```c
void parse_packet(struct packet *pkt, const char *data, int len) {
    char header[64];
    memcpy(header, data, len);
    process_header(header);
}

int handle_request(struct request *req) {
    struct session *sess = lookup_session(req->session_id);
    return sess->handler(req);
}

static void log_debug(const char *msg) {
    if (msg) printf("%s\\n", msg);
}

int process_attr(struct attr_value *av) {
    return av->value.str_val->length;
}
```

Provide a detailed security analysis.\
"""

FEWSHOT_EXAMPLE_ASSISTANT = """\
`parse_packet`: `data` and `len` come from the network. Copies `len` \
bytes into 64-byte stack buffer with no bounds check — overflow if \
`len > 64`. `handle_request`: `lookup_session()` can return NULL but \
result is dereferenced. `log_debug`: safe, already checks NULL. \
`process_attr`: accesses union member without checking type tag.

```json
[
  {{"severity": "critical", "title": "Stack buffer overflow via unchecked len", "function": "parse_packet()", "description": "memcpy copies attacker-controlled len bytes into 64-byte stack buffer without bounds check"}},
  {{"severity": "high", "title": "NULL deref on failed session lookup", "function": "handle_request()", "description": "lookup_session() may return NULL for unknown session_id but result is dereferenced unconditionally"}},
  {{"severity": "high", "title": "Type confusion on union access", "function": "process_attr()", "description": "Accesses av->value.str_val without checking av->type. If av is from parsed input, wrong union member is read"}}
]
```\
"""

CONTEXT_GEN_PROMPT = """\
You are preparing a security briefing for a vulnerability researcher. \
Write a concise (~250 word) context briefing covering:

1. What this code does and where it sits in the project
2. How untrusted input reaches this code (network, file, API?)
3. Which variables/fields carry attacker-controlled data — name them, \
   trace the data flow from entry point to usage
4. All fixed-size buffers and size constants — name them with sizes. \
   If sizes are defined by named constants (macros, #defines), use \
   GREP to find the actual numeric value. State the resolved value \
   explicitly, e.g. "buf[EVP_MAX_MD_SIZE] where EVP_MAX_MD_SIZE=64"
5. Dangerous data flows: attacker-controlled data → fixed-size buffer. \
   Name source, destination, function, and the numeric buffer size \
   for each
6. Parameters that could be NULL from malformed input but are \
   dereferenced without checks
7. Tagged unions or variant types accessed without type-tag validation. \
   Note whether the code checks the type tag before accessing \
   type-specific union members
8. Which functions are public API vs static helpers (and whether \
   static helpers are called safely)
9. What bug classes are most likely given this code's structure

Name actual variables and constants from the code. Do not find \
vulnerabilities — just provide context. Use your training knowledge \
of this project where helpful.

GREP TOOL: You can search the codebase by including GREP: pattern \
in your response. Use this to look up the actual values of constants, \
find callers of functions, or check how data flows between files. \
The results will be appended to your briefing.\
"""

TRIAGE_PROMPT_TEMPLATE = """\
A vulnerability scanner flagged this in {project_name}. Is it real?

Be skeptical — most scanner findings are false positives.

RULES:
- VALID: the bug is real AND an external attacker can trigger it to \
  cause meaningful harm (crash, code execution, data corruption, auth \
  bypass). The attacker must control the input that triggers the bug.
- INVALID: the bug pattern does not exist, OR it is not attacker-reachable \
  (only trusted internal callers), OR a concrete defense prevents it, \
  OR it is a code quality issue not a security vulnerability (e.g. \
  data race on diagnostic state, missing NULL check on internal-only \
  API, undefined behavior only in debug builds).
- UNCERTAIN: only if you genuinely cannot determine.

ABSENCE OF DEFENSE: If the bug pattern clearly exists, the input \
comes from an untrusted source, and you searched for a defense but \
did not find one, lean toward VALID rather than UNCERTAIN. Not \
having verified every upstream caller is not a reason to mark \
UNCERTAIN — only cite a defense if you can name the specific \
function and show it is sufficient.

CRITICAL: When you cite any defense — a size limit, a NULL check, a \
type validation — you must verify it actually works. Look up the \
actual numeric values. Do the arithmetic. Show your work. "There \
exists a bound" is NOT the same as "the bound is sufficient." Never \
skip the verification step.

FOLLOW CONSTANTS: When you encounter a named constant in code or \
grep results, you MUST \
grep for its #define to find the actual numeric value. A constant \
name is not a verified bound — only its resolved value is. If a \
function receives a size parameter, grep for its callers to see what \
value they pass.

IMPORTANT: If your own analysis leads to a conclusion, do not then \
contradict it in the same response. If you verify a defense and find \
it insufficient, that is your answer — do not keep searching for \
reasons to change your mind. Trust your own reasoning.

If you believe a defense exists that you haven't verified, you must \
either name the specific function/line that implements it or grep \
for it. Vague references to "assumptions in this codebase" or \
"other code probably handles this" are not valid defenses. If you \
cannot point to it or find it, it does not exist.

GREP TOOL: Include a grep pattern in the JSON to search the codebase. \
Use this to look up values, check implementations, and verify defenses. \
GREP PATTERNS: Use function/variable/constant names as patterns, e.g. \
"MAX_BUF_SIZE", "parse_input(", "buflen". Do NOT prefix patterns with \
file paths like "src/foo/bar.c:symbol" — that searches for the literal \
string inside files and will return nothing. To find callers of a \
function, grep for its name. To resolve a constant, grep for its name \
to find its #define.

Use your knowledge of {project_name} for intuition, but verify \
specifics via grep. Do not invent defenses.

Respond ONLY with JSON:
{{"reasoning": "Analyze the evidence. State your conclusion clearly.", \
"crux": "the single key fact the verdict depends on", \
"grep": "search_pattern to verify the crux", \
"verdict": "VALID/INVALID/UNCERTAIN"}}

---

**Reported vulnerability:**
{finding}

**Code from {filepath}:**
```c
{code}
```\
"""

USER_PROMPT_TEMPLATE = """\
Analyze the following source file for zero-day vulnerabilities.

File: {filepath}

```c
{code}
```

Provide a detailed security analysis.\
"""

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def load_api_keys():
    keys = {}
    for var in ("OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        val = os.environ.get(var)
        if val:
            keys[var] = val
    return keys


def resolve_backend(model, keys):
    openrouter_api_url = os.environ.get("OPENROUTER_API_URL", OPENROUTER_API_URL)
    openai_api_url = os.environ.get("OPENAI_API_URL", OPENAI_API_URL)

    if "/" in model:
        api_key = keys.get("OPENROUTER_API_KEY")
        if not api_key:
            print(
                f"❌ Model '{model}' uses OpenRouter (provider/model format) "
                "but OPENROUTER_API_KEY is not set.",
                file=sys.stderr,
            )
            print("   Set it with:  export OPENROUTER_API_KEY=sk-or-...", file=sys.stderr)
            sys.exit(1)
        return openrouter_api_url, api_key, model, {
            "HTTP-Referer": "https://github.com/weareaisle/nano-analyzer",
            "X-Title": "nano-analyzer",
        }

    api_key = keys.get("OPENAI_API_KEY")
    if not api_key:
        print(
            f"❌ Model '{model}' uses OpenAI but OPENAI_API_KEY is not set.",
            file=sys.stderr,
        )
        print("   Set it with:  export OPENAI_API_KEY=sk-...", file=sys.stderr)
        sys.exit(1)
    return openai_api_url, api_key, model, {}


_http_session = None
_http_lock = threading.Lock()
_api_semaphore = None


def _get_session():
    global _http_session
    if _http_session is None:
        with _http_lock:
            if _http_session is None:
                _http_session = urllib.request.build_opener(
                    urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(),
                )
    return _http_session


def init_api_semaphore(max_concurrent):
    global _api_semaphore
    _api_semaphore = threading.Semaphore(max_concurrent)


def call_llm(model, messages, keys, json_mode=False, max_retries=3, reasoning_effort=None):
    api_url, api_key, model_name, extra_headers = resolve_backend(model, keys)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **extra_headers,
    }
    payload = {"model": model_name, "messages": messages}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort

    session = _get_session()

    for attempt in range(max_retries):
        time.sleep(
            random.uniform(0.1, 3.0)
            if attempt == 0
            else 2 ** attempt + random.uniform(0, 2)
        )
        try:
            t0 = time.time()
            with _api_semaphore:
                request = urllib.request.Request(
                    api_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with session.open(request, timeout=120) as resp:
                    status_code = resp.status
                    response_text = resp.read().decode("utf-8", errors="replace")
                elapsed = time.time() - t0

            if status_code == 429 or status_code >= 500:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue

            if status_code != 200:
                raise RuntimeError(f"API {status_code}: {response_text[:200]}")

            data = json.loads(response_text)
            if "error" in data:
                raise RuntimeError(f"API error: {data['error']}")

            content = data["choices"][0]["message"]["content"]
            if content is None:
                content = data["choices"][0]["message"].get("reasoning_content") or ""
            usage = data.get("usage", {})
            return content, usage, elapsed

        except urllib.error.HTTPError as e:
            status_code = e.code
            response_text = ""
            try:
                response_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                response_text = str(e)

            if status_code == 429 or status_code >= 500:
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue

            raise RuntimeError(f"API {status_code}: {response_text[:200]}")

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            ConnectionResetError,
            OSError,
        ) as e:
            if attempt == max_retries - 1:
                raise RuntimeError(f"Connection failed after {max_retries} retries: {e}")
            time.sleep(2 ** attempt + random.uniform(0, 1))

    raise RuntimeError("Max retries exceeded")
# ---------------------------------------------------------------------------
# Severity parsing
# ---------------------------------------------------------------------------

def _extract_json(text):
    """Try to extract a JSON object or array from text that might have
    markdown fences or surrounding prose."""
    text = text.strip()
    fence = re.search(r'```(?:json)?\s*\n?(.*?)```', text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Repair common nano model JSON malformations (scan output arrays only)
    if '"severity"' in text:
        repaired = text
        # `4: {` instead of `{` in arrays
        repaired = re.sub(r',?\s*\d+\s*:\s*\{', ', {', repaired)
        repaired = re.sub(r'^\[\s*,', '[', repaired.strip())
        # Invalid backslash escapes: \' \0 etc. (not valid in JSON)
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', repaired)
        if repaired != text:
            try:
                return json.loads(repaired)
            except (json.JSONDecodeError, ValueError):
                pass

        # Last resort: extract individual JSON objects from broken arrays
        objects = []
        for m in re.finditer(r'\{\s*"severity"', text):
            depth = 0
            for i in range(m.start(), len(text)):
                if text[i] == '{': depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        chunk = text[m.start():i + 1]
                        chunk = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', chunk)
                        try:
                            objects.append(json.loads(chunk))
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
        if objects:
            return objects

    for start_char, end_char in [('[', ']'), ('{', '}')]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == start_char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def parse_findings(text):
    """Parse findings from JSON array, with fallback to regex."""
    # Method 1: >>> marker lines
    marker_pattern = re.compile(
        r'^>>>\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*(.+)',
        re.MULTILINE | re.IGNORECASE,
    )
    marker_matches = list(marker_pattern.finditer(text))
    if marker_matches:
        findings = []
        for m in marker_matches:
            sev = m.group(1).lower()
            rest = m.group(2).strip()
            parts = rest.split("|", 2)
            title = parts[0].strip()
            body = rest
            findings.append({"severity": sev, "title": title, "body": body})
        return findings

    # Method 2: JSON
    parsed = _extract_json(text)

    if isinstance(parsed, dict) and "severity" in parsed:
        parsed = [parsed]

    if isinstance(parsed, dict) and "findings" in parsed:
        parsed = parsed["findings"]

    if isinstance(parsed, list):
        findings = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            sev = item.get("severity", "medium").lower()
            if sev == "none":
                continue
            findings.append({
                "severity": sev,
                "title": item.get("title", "Untitled finding"),
                "body": item.get("description", "") + ("\n\nFix: " + item["fix"] if item.get("fix") else ""),
            })
        return findings

    _BUG_KEYWORD = re.compile(
        r'(?:overflow|underflow|use.after.free|double.free|null.pointer|'
        r'null.deref|out.of.bounds|oob|buffer|race|deadlock|'
        r'injection|bypass|escalat|uncheck|missing.check|missing.bound|'
        r'missing.valid|unbounded|unchecked|integer.overflow|'
        r'uaf|memcpy|sprintf|strcpy|strcat|format.string|'
        r'denial.of.service|dos\b|crash|panic|corrupt|'
        r'leak|disclosure|uninitiali|dangling|stale|'
        r'sequence|replay|shift|xdr|length|size)',
        re.IGNORECASE,
    )
    _JUNK_TITLE = re.compile(
        r'(?:^summary|^overview|^what (?:this|to|i) |^threat model|'
        r'^overall|^conclusion|^next step|^recommend|^note|'
        r'^checklist|^audit |^action|^practical |'
        r'^.?level\b|^/info|^.?impact\b|^.?risk\b|'
        r'^.?confidence\b|exploitation path|candidates|'
        r'^concurrency consider|^other |^ssues|^oncrete )',
        re.IGNORECASE,
    )
    # Filter out function-signature headings (documentation, not findings)
    _FUNC_SIG = re.compile(r'^[`\s]*\w+[\w_]*\s*[\(/]', re.IGNORECASE)

    findings = []
    heading_pattern = re.compile(
        r'^#{1,4}\s+'
        r'(?:\d+[\.\)]\s*'                  # "## 1) Title" or "## 2. Title"
        r'|(?:critical|high|medium|low)\b'   # "## High severity: ..."
        r'|[>`\w]'                           # "## `function_name()`" or any heading
        r')'
        r'(.*)',
        re.MULTILINE | re.IGNORECASE,
    )
    matches = list(heading_pattern.finditer(text))
    if matches:
        for i, m in enumerate(matches):
            title = m.group(1).strip().strip("*").strip()
            title = re.sub(r'^severity\s*[:/]\s*', '', title, flags=re.IGNORECASE)
            title = re.sub(r'^[\(\[]?\s*(?:critical|high|medium|low|informational)\s*[\)\]]?\s*[:/]?\s*',
                           '', title, flags=re.IGNORECASE).strip()
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            section = text[start:end]
            if _JUNK_TITLE.search(title):
                continue
            if _FUNC_SIG.search(title):
                continue
            if not _BUG_KEYWORD.search(title) and not _BUG_KEYWORD.search(section[:300]):
                continue
            sev = "medium"
            for level in SEVERITY_LEVELS:
                if re.search(r'\b' + level + r'\b', section, re.IGNORECASE):
                    sev = level
                    break
            findings.append({"severity": sev, "title": title, "body": section.strip()})

    if not findings:
        for level in SEVERITY_LEVELS:
            if re.search(r'\b' + level + r'\b', text, re.IGNORECASE):
                findings.append({"severity": level, "title": "Unstructured finding", "body": text})
                break

    return findings


def count_severities(text):
    findings = parse_findings(text)
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


def top_severity(sevs):
    for level in SEVERITY_LEVELS:
        if sevs.get(level, 0) > 0:
            return level
    return "clean"

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def discover_files(path, extensions, max_chars):
    """Walk a path (file or dir) and return (scannable, skipped) lists."""
    scannable = []
    skipped = []

    if os.path.isfile(path):
        candidates = [path]
    else:
        candidates = []
        for root, _, fnames in os.walk(path):
            for fn in sorted(fnames):
                candidates.append(os.path.join(root, fn))

    for filepath in candidates:
        if os.path.islink(filepath):
            skipped.append((filepath, "symlink"))
            continue

        ext = os.path.splitext(filepath)[1].lower()
        if extensions and ext not in extensions:
            skipped.append((filepath, "extension"))
            continue

        try:
            size = os.path.getsize(filepath)
        except OSError:
            skipped.append((filepath, "unreadable"))
            continue

        if size > max_chars:
            skipped.append((filepath, f"too large ({size:,} bytes)"))
            continue

        try:
            with open(filepath) as f:
                content = f.read()
            line_count = content.count("\n")
            char_count = len(content)
        except (OSError, UnicodeDecodeError):
            skipped.append((filepath, "unreadable/binary"))
            continue

        if char_count > max_chars:
            skipped.append((filepath, f"too large ({char_count:,} chars)"))
            continue

        scannable.append({
            "filepath": filepath,
            "lines": line_count,
            "chars": char_count,
        })

    return scannable, skipped

# ---------------------------------------------------------------------------
# Core scan logic (per-file, runs in thread)
# ---------------------------------------------------------------------------

def scan_single_file(filepath, code, display_name, model, keys, repo_dir=None):
    """Run the two-stage scan on a single file. Returns result dict."""
    result = {
        "file": filepath,
        "display_name": display_name,
        "model": model,
    }

    try:
        # Stage 1: generate context (with optional grep)
        ctx_messages = [
            {"role": "system", "content": CONTEXT_GEN_PROMPT},
            {"role": "user", "content": f"File: {display_name}\n\n```\n{code}\n```"},
        ]
        context, ctx_usage, ctx_elapsed = call_llm(model, ctx_messages, keys)

        # Execute any grep requests from context generation
        if repo_dir:
            ctx_greps = execute_grep_requests(context, repo_dir)
            if ctx_greps:
                context += f"\n\n[GREP RESULTS from codebase]:\n{ctx_greps}"

        result["context"] = context
        result["context_tokens"] = ctx_usage.get("total_tokens", 0)
        result["context_elapsed"] = round(ctx_elapsed, 1)

        # Stage 2: vulnerability scan (with few-shot example)
        scan_messages = [
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT + "\n\n"
             "Security context for the file being analyzed:\n" + context},
            {"role": "user", "content": FEWSHOT_EXAMPLE_USER},
            {"role": "assistant", "content": FEWSHOT_EXAMPLE_ASSISTANT},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(
                filepath=display_name, code=code)},
        ]
        report, scan_usage, scan_elapsed = call_llm(model, scan_messages, keys)
        result["report"] = report
        result["prompt_tokens"] = scan_usage.get("prompt_tokens", 0)
        result["completion_tokens"] = scan_usage.get("completion_tokens", 0)
        result["total_tokens"] = scan_usage.get("total_tokens", 0)
        result["scan_elapsed"] = round(scan_elapsed, 1)
        result["total_elapsed"] = round(ctx_elapsed + scan_elapsed, 1)
        result["severities"] = count_severities(report)
        result["status"] = "ok"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["severities"] = {level: 0 for level in SEVERITY_LEVELS}

    return result


def extract_findings(report):
    """Extract findings as (title, text) tuples for triage."""
    parsed = parse_findings(report)
    results = []
    for f in parsed:
        fid = f.get("id", "")
        prefix = f"{fid} " if fid else ""
        results.append((
            f"{prefix}{f['title']}",
            f"[{f['severity'].upper()}] {prefix}{f['title']}\n\n{f['body']}",
        ))
    return results


MAX_GREP_REQUESTS = 3
MAX_GREP_LINES = 30
MAX_GREP_LINE_LEN = 2000


_csearch_path = None
_csearch_index = None
_rg_path = shutil.which("rg")


def init_grep_index(repo_dir):
    """Build a csearch index for the repo if csearch is available."""
    global _csearch_path, _csearch_index, _rg_path
    _csearch_path = shutil.which("csearch")
    cindex_path = shutil.which("cindex")
    _rg_path = shutil.which("rg")

    if not _csearch_path or not cindex_path:
        _csearch_path = None
        return

    _csearch_index = f"/tmp/nano_aisle_{os.path.basename(repo_dir)}.csearchindex"
    if os.path.exists(_csearch_index):
        return

    print(f"📇 Building search index for {repo_dir}...")
    try:
        subprocess.run(
            [cindex_path, repo_dir],
            capture_output=True, timeout=300,
            env={**os.environ, "CSEARCHINDEX": _csearch_index},
        )
        print(f"📇 Index ready: {_csearch_index}")
    except Exception as e:
        print(f"📇 Index failed: {e} — falling back to ripgrep")
        _csearch_path = None


def execute_grep_requests(response_text, repo_dir):
    """Parse grep requests from triage response, execute them, return results.
    Uses csearch if indexed, falls back to ripgrep."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return None

    requests = []

    # Explicit GREP: lines
    for m in re.finditer(r'GREP:\s*(.+)', response_text, re.IGNORECASE):
        requests.append(m.group(1).strip().strip('`').strip())

    # Prose-style: "grep for `pattern`" or "grep for pattern"
    for m in re.finditer(r'[Gg][Rr][Ee][Pp]\s+(?:for\s+)?[`"]([^`"]+)[`"]', response_text):
        val = m.group(1).strip()
        if val and val not in requests:
            requests.append(val)

    # Without backticks: "grep for function_name(" or "GREP function_name"
    for m in re.finditer(r'[Gg][Rr][Ee][Pp]\s+(?:for\s+)?(\w[\w_:.*]+\(?)', response_text):
        val = m.group(1).strip()
        if val and len(val) > 6 and val not in requests:
            requests.append(val)

    if not requests:
        return None

    # Junk grep terms the model accidentally produces (from prose near "GREP")
    _GREP_JUNK = {"results", "call", "code", "function", "value",
                  "NULL", "null", "type", "data", "return", "void",
                  "true", "false", "the", "this", "that", "from",
                  "verification", "verifications", "verified", "verify",
                  "evidence", "confirm", "confirmed", "confirms",
                  "output", "outputs", "search", "searches",
                  "pattern", "patterns", "required", "provided",
                  "shown", "needed", "following", "whether",
                  "checked", "checking", "matched", "matches",
                  "returned", "returns", "failed", "missing"}

    def _unescape(s):
        """Strip regex escapes and stray punctuation for literal search."""
        s = re.sub(r'\\[bBdDwWsS]', '', s)
        s = re.sub(r'\\(.)', r'\1', s)
        s = s.strip().strip('"\'`')
        return s

    def _simplify_pattern(pattern):
        """Extract the core identifier from a complex code pattern."""
        identifiers = re.findall(r'[a-zA-Z_]\w*(?:->[\w]+)*', pattern)
        identifiers.sort(key=len, reverse=True)
        for ident in identifiers:
            if len(ident) > 5 and ident not in _GREP_JUNK:
                return ident
        return None

    # Expand compound patterns and clean up
    expanded = []
    for raw in requests[:MAX_GREP_REQUESTS]:
        raw = raw.strip()
        # Split on | and unescape each part
        parts = raw.split("|") if "|" in raw else [raw]
        for part in parts:
            cleaned = _unescape(part)
            if not cleaned or len(cleaned) < 3 or cleaned in _GREP_JUNK:
                continue
            # Strip file path prefixes (e.g. "sys/foo/bar.c:symbol" → "symbol")
            path_prefix = re.match(r'[\w/\\]+\.\w+[:\s]+(.+)', cleaned)
            if path_prefix:
                cleaned = path_prefix.group(1).strip()
                if not cleaned or len(cleaned) < 3 or cleaned in _GREP_JUNK:
                    continue
            # Skip purely numeric patterns (line numbers extracted from file:line refs)
            if re.match(r'^\d+[:\s]*$', cleaned):
                continue
            # If pattern has commas/spaces (too specific), extract identifier
            if ", " in cleaned or len(cleaned) > 60:
                simplified = _simplify_pattern(cleaned)
                if simplified:
                    cleaned = simplified
            expanded.append(cleaned)

    def _run_grep(pattern, repo_dir, fixed=True):
        """Run a single grep, return raw output or empty string."""
        try:
            if _csearch_path and _csearch_index:
                # csearch uses regex — escape special chars for literal match
                escaped = re.escape(pattern) if fixed else pattern
                proc = subprocess.run(
                    [_csearch_path, "-n", escaped],
                    capture_output=True, text=True, timeout=10,
                    env={**os.environ, "CSEARCHINDEX": _csearch_index},
                    errors="replace",
                )
                raw = proc.stdout.strip()
                if raw:
                    raw = raw.replace(repo_dir.rstrip("/") + "/", "")
                    lines_filtered = [l for l in raw.splitlines()
                                      if re.search(r'\.[ch]:', l)]
                    return "\n".join(lines_filtered)
                return ""
            else:
                if not _rg_path:
                    return ""
                flags = ["--fixed-strings"] if fixed else []
                proc = subprocess.run(
                    [_rg_path, "--no-heading", "-n"] + flags +
                    ["-g", "*.c", "-g", "*.h", pattern],
                    capture_output=True, text=True, timeout=60,
                    cwd=repo_dir, errors="replace",
                )
                return proc.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    results = []
    for pattern in expanded[:MAX_GREP_REQUESTS * 2]:
        try:
            # Detect if pattern uses regex syntax
            is_regex = bool(re.search(r'(?<![\\])[.*+?{}|^$]', pattern))

            # Try search
            raw = _run_grep(pattern, repo_dir, fixed=not is_regex)

            # If no results and pattern looks complex, simplify and retry
            if not raw and any(c in pattern for c in "(),-> "):
                simplified = _simplify_pattern(pattern)
                if simplified and simplified != pattern:
                    raw = _run_grep(simplified, repo_dir, fixed=True)
                    if raw:
                        pattern = f"{pattern} (simplified to: {simplified})"

            all_lines = raw.splitlines() if raw else []
            # Prioritize #define and .h lines (definitions) over usage sites
            def _line_priority(l):
                if '#define' in l: return 0
                if '.h:' in l: return 1
                return 2
            all_lines.sort(key=_line_priority)
            lines = all_lines[:MAX_GREP_LINES]
            truncated = []
            for line in lines:
                if len(line) > MAX_GREP_LINE_LEN:
                    truncated.append(line[:MAX_GREP_LINE_LEN] + "...")
                else:
                    truncated.append(line)
            output = "\n".join(truncated) if truncated else "(no matches in repo)"
            output = output.replace("\x00", "")
            results.append(f"GREP `{pattern}`:\n```\n{output}\n```")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            results.append(f"GREP `{pattern}`: (search failed)")

    return "\n\n".join(results)


def _condense_prior_greps(reasoning_text, max_lines_per_pattern=3):
    """Replace full grep output in prior-round reasoning with a compact
    summary that preserves key evidence without context bloat."""
    match = re.search(r'\n\n\[GREP RESULTS[^\]]*\]:\n', reasoning_text)
    if not match:
        return reasoning_text

    before = reasoning_text[:match.start()]
    grep_section = reasoning_text[match.end():]

    condensed = []
    for pattern, content in re.findall(
        r'GREP `([^`]*)`:\n```\n(.*?)\n```', grep_section, re.DOTALL
    ):
        content = content.strip()
        if not content or content == '(no matches in repo)':
            condensed.append(f"  - `{pattern}`: (no matches)")
        else:
            lines = [l for l in content.split('\n') if l.strip()]
            shown = lines[:max_lines_per_pattern]
            extra = len(lines) - len(shown)
            for line in shown:
                condensed.append(f"  - {line.strip()}")
            if extra > 0:
                condensed.append(f"    (+{extra} more matches)")

    if condensed:
        return before + "\n\n[Prior grep evidence]:\n" + "\n".join(condensed)
    return before


def triage_finding(finding_title, finding_text, code, filepath,
                   project_name, model, keys, prior_reasoning=None,
                   repo_dir=None, reasoning_effort=None, file_context=None):
    """Stage 3: Skeptical triage of a single finding. Returns verdict dict."""
    prompt = TRIAGE_PROMPT_TEMPLATE.format(
        project_name=project_name,
        finding=finding_text,
        filepath=filepath,
        code=code,
    )

    if file_context:
        prompt += (
            "\n\n**Security context for this file:**\n"
            + file_context[:2000]  # cap to avoid bloating
        )

    if prior_reasoning:
        prompt += (
            "\n\n---\n\n"
            "Prior reviewers have weighed in below. Their reasoning is "
            "SPECULATIVE — it may contain errors or unfounded assumptions.\n\n"
            "Your job is NOT to repeat their analysis. Instead:\n"
            "- Find arguments they MISSED — new attack paths, new \n"
            "  defenses, different code paths, different callers\n"
            "- If they all focused on one aspect, look at a DIFFERENT one\n"
            "- Verify any cited defense with actual values (use GREP)\n"
            "- Consider angles no prior reviewer raised: what about \n"
            "  error paths? race conditions? integer edge cases? caller \n"
            "  contracts? platform differences?\n"
            "- Do NOT rehash the same argument — add new information\n\n"
        )
        for i, (verdict, reasoning) in enumerate(prior_reasoning, 1):
            prompt += f"**Reviewer {i}**:\n{reasoning}\n\n"

    messages = [
        {"role": "system", "content": "You are a security engineer triaging "
         "vulnerability reports. For each finding, answer: "
         "(1) Is the bug pattern real in the code? "
         "(2) Can an attacker reach it through untrusted input? Trace "
         "the data flow backward from the bug to its origin. "
         "(3) If a defense is cited, is it actually sufficient? If you "
         "find a numeric constant, grep for its value before concluding. "
         "(4) Even if the bug is real, is it security-relevant? A data "
         "race on diagnostic state, a missing NULL check on an internal "
         "API that only trusted callers use, or undefined behavior only "
         "in debug builds are code quality issues, NOT security "
         "vulnerabilities — mark these INVALID. "
         "Use GREP to verify. Do not guess."},
        {"role": "user", "content": prompt},
    ]

    try:
        response, usage, elapsed = call_llm(model, messages, keys, json_mode=True,
                                           reasoning_effort=reasoning_effort)

        verdict = "UNCERTAIN"
        reasoning = response

        parsed = _extract_json(response)
        if isinstance(parsed, dict):
            v = parsed.get("verdict", "").upper()
            if v in ("VALID", "INVALID", "UNCERTAIN"):
                verdict = v
            reasoning = parsed.get("reasoning", response)
            crux = parsed.get("crux", "")
            if crux:
                reasoning += f"\n\nCRUX: {crux}"

            grep_req = parsed.get("grep", "")
            if grep_req:
                grep_req = re.sub(r'^GREP:\s*', '', grep_req, flags=re.IGNORECASE)
                grep_req = grep_req.strip('`"\'')
                if grep_req:
                    reasoning += f"\nGREP: {grep_req}"
        else:
            clean = re.sub(r'[*#\-\s]+', ' ', response[:300]).strip().upper()
            if "INVALID" in clean[:30]:
                verdict = "INVALID"
            elif "VALID" in clean[:30]:
                verdict = "VALID"
            elif "UNCERTAIN" in clean[:30]:
                verdict = "UNCERTAIN"

        return {
            "finding_title": finding_title,
            "verdict": verdict,
            "reasoning": reasoning,
            "elapsed": round(elapsed, 1),
            "tokens": usage.get("total_tokens", 0),
        }
    except Exception as e:
        return {
            "finding_title": finding_title,
            "verdict": "ERROR",
            "reasoning": str(e),
            "elapsed": 0,
            "tokens": 0,
        }


VERDICT_EMOJI = {
    "VALID": "✅",
    "INVALID": "❌",
    "UNCERTAIN": "❓",
    "ERROR": "💥",
}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

print_lock = threading.Lock()


def print_logo(offset_spaces: int = 5) -> str:
    logo_str = f"""\033[32m
            I   I
           AI   IA
         AA#I   I#AA
       AA##V     V##AA
     AA###V       V###AA
   AA####V         V####AA
TTT#####V           V#####TTT
III####V             V####III
III###V               V###III
III##V  \033[30mNANO-ANALYZER\033[32m  V##III
III#V    \033[90mversion \033[30m{VERSION}    \033[32mV#III
IIIV                     VIII
          \033[92mA I S L E
    \033[0m"""

    logo_str = "".join([f"{' ' * offset_spaces}{line}\n" for line in logo_str.split("\n")])

    print(logo_str)

    return logo_str


def run_scan(args):
    max_conn = args.max_connections or (args.parallel + args.triage_parallel)
    init_api_semaphore(max_conn)
    keys = load_api_keys()

    # Discover files
    ext_set = DEFAULT_EXTENSIONS

    scannable, skipped = discover_files(args.path, ext_set, args.max_chars)

    if not scannable:
        print("❌ No scannable files found.")
        return

    total_lines = sum(f["lines"] for f in scannable)
    total_chars = sum(f["chars"] for f in scannable)

    # Compute display base for relative paths
    if os.path.isdir(args.path):
        base_path = os.path.abspath(args.path)
    else:
        base_path = os.path.dirname(os.path.abspath(args.path))

    # Resolve grep/repo directory
    if args.repo_dir:
        repo_dir = args.repo_dir
    elif os.path.isfile(args.path):
        repo_dir = os.path.dirname(os.path.abspath(args.path))
    else:
        repo_dir = os.path.abspath(args.path)

    # Timestamp for output directory
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    if args.output_dir:
        out_dir = args.output_dir
    else:
        out_dir = os.path.join(os.path.expanduser("~/nano-analyzer-results"), timestamp)
    os.makedirs(out_dir, exist_ok=True)

    # Triage config
    triage_threshold = args.triage_threshold
    triage_rounds = args.triage_rounds
    project_name = args.project or os.path.basename(os.path.abspath(args.path))
    if args.repo_dir:
        init_grep_index(repo_dir)
    do_triage = triage_threshold is not None
    verbose_triage = args.verbose_triage
    thresh_idx = SEVERITY_LEVELS.index(triage_threshold) if do_triage else -1
    triage_counter = [0]  # completed triages
    triage_total = [0]    # total triages submitted (grows as scans find findings)
    triage_semaphore = threading.Semaphore(args.triage_parallel) if do_triage else None
    active_scans = [0]
    active_triages = [0]
    triage_valid_count = [0]
    triage_invalid_count = [0]
    triage_uncertain_count = [0]

    # Pre-scan summary
    print_logo()
    print("🔍 nano-analyzer vulnerability scanner")
    print(f"📂 Target: {os.path.abspath(args.path)}")
    print(f"🔎 Grep dir: {repo_dir}")
    print(f"📄 {len(scannable)} files to scan ({total_lines:,} lines, {total_chars:,} chars)")
    if skipped:
        skip_ext = sum(1 for _, r in skipped if r == "extension")
        skip_size = sum(1 for _, r in skipped if "large" in r)
        skip_other = len(skipped) - skip_ext - skip_size
        parts = []
        if skip_ext:
            parts.append(f"{skip_ext} wrong extension")
        if skip_size:
            parts.append(f"{skip_size} too large")
        if skip_other:
            parts.append(f"{skip_other} unreadable")
        print(f"   ⏭️  {len(skipped)} skipped ({', '.join(parts)})")
    print(f"🤖 Model: {args.model}")
    print(f"⚡ Parallelism: {args.parallel} scan, {args.triage_parallel} triage")
    print(f"💾 Results → {out_dir}/")
    if do_triage:
        rounds_str = f", {triage_rounds} rounds" if triage_rounds > 1 else ""
        print(f"🔬 Triage: {triage_threshold}+ findings → skeptical review ({rounds_str.lstrip(', ')})" if triage_rounds > 1 else f"🔬 Triage: {triage_threshold}+ findings → skeptical review")
    print()

    # Run scans (and inline triage)
    results = []
    all_triage_results = []
    completed = 0
    total = len(scannable)
    scan_start = time.time()

    def process_file(file_info):
        nonlocal completed
        filepath = file_info["filepath"]

        with open(filepath) as f:
            code = f.read()

        display_name = os.path.relpath(filepath, base_path)

        with print_lock:
            active_scans[0] += 1
        try:
            result = scan_single_file(
                filepath, code, display_name,
                args.model, keys,
                repo_dir=repo_dir,
            )
        finally:
            with print_lock:
                active_scans[0] -= 1

        result["lines"] = file_info["lines"]
        result["chars"] = file_info["chars"]
        result["timestamp"] = timestamp

        # Save individual results
        safename = display_name.replace("/", "_").replace("\\", "_")
        md_path = os.path.join(out_dir, f"{safename}.md")
        json_path = os.path.join(out_dir, f"{safename}.json")

        if result["status"] == "ok":
            with open(md_path, "w") as f:
                f.write(f"# Scan: {display_name}\n\n")
                f.write(result["report"])

            ctx_md_path = os.path.join(out_dir, f"{safename}.context.md")
            with open(ctx_md_path, "w") as f:
                f.write(f"# Context: {display_name}\n\n")
                f.write(result.get("context", "(no context generated)"))

            with open(json_path, "w") as f:
                json.dump(result, f, indent=2)

        # Live scan output
        with print_lock:
            completed += 1
            sevs = result["severities"]
            short_name = os.path.basename(filepath)
            elapsed = result.get("total_elapsed", 0)
            cw = len(str(total))

            sc = active_scans[0]
            tc = active_triages[0]
            ts = datetime.now().strftime("%H:%M:%S")
            load = f"[LLMs running S:{sc} T:{tc}]"

            if result["status"] == "error":
                print(f"  {ts} [file {completed:>{cw}}/{total}] ❌ {short_name}  ERROR: {result['error'][:50]}  {load}")
            else:
                dots = ""
                for lev, em in [("critical", "🔴"), ("high", "🟠"),
                                ("medium", "🟡"), ("low", "🔵")]:
                    dots += em * sevs.get(lev, 0)

                ctx_link = os.path.join(out_dir, f"{safename}.context.md")
                scan_link = os.path.join(out_dir, f"{safename}.md")
                if dots:
                    print(f"  {ts} [file {completed:>{cw}}/{total}] {dots} {short_name}  {elapsed:.0f}s  {load}")
                else:
                    print(f"  {ts} [file {completed:>{cw}}/{total}] ⬜ {short_name}  {elapsed:.0f}s  {load}")
                if result["status"] == "ok":
                    print(f"         📋 {ctx_link}")
                    print(f"         📄 {scan_link}")

        # Queue triage work (non-blocking — fires and forgets into triage executor)
        result["_triage_pending"] = []
        if do_triage and result["status"] == "ok":
            needs_triage = any(
                result["severities"].get(lev, 0) > 0
                for lev in SEVERITY_LEVELS[:thresh_idx + 1]
            )
            if needs_triage:
                findings = extract_findings(result["report"])
                to_triage = []
                for title, text in findings:
                    finding_sev = None
                    for lev in SEVERITY_LEVELS:
                        if re.search(r'\b' + lev + r'\b', text[:200], re.IGNORECASE):
                            finding_sev = lev
                            break
                    if finding_sev is None or SEVERITY_LEVELS.index(finding_sev) > thresh_idx:
                        continue
                    to_triage.append((title, text))

                file_context = result.get("context", "")

                def _triage_one_finding(t_title, t_text, t_code, t_display, t_short):
                    """Run all triage rounds for one finding, print result, append."""
                    try:
                        return _triage_one_finding_inner(t_title, t_text, t_code, t_display, t_short)
                    except Exception as e:
                        with print_lock:
                            ts = datetime.now().strftime("%H:%M:%S")
                            print(f"  {ts} ❌ TRIAGE ERROR {t_short}: {t_title[:40]}... — {e}")

                def _triage_one_finding_inner(t_title, t_text, t_code, t_display, t_short):
                    round_verdicts = []
                    prior = None
                    for rn in range(1, triage_rounds + 1):
                        with triage_semaphore:
                            with print_lock:
                                active_triages[0] += 1
                            try:
                                tv = triage_finding(
                                    t_title, t_text, t_code, t_display,
                                    project_name, args.model, keys,
                                    prior_reasoning=prior,
                                    repo_dir=repo_dir,
                                    file_context=file_context,
                                )
                            except Exception as e:
                                tv = {
                                    "finding_title": t_title,
                                    "verdict": "UNCERTAIN",
                                    "reasoning": f"Triage error: {e}",
                                }
                            finally:
                                with print_lock:
                                    active_triages[0] -= 1
                        tv["file"] = t_display
                        tv["round"] = rn
                        round_verdicts.append(tv)

                        # Print partial progress per round
                        if triage_rounds > 1 and verbose_triage:
                            history = "".join(VERDICT_EMOJI.get(rv["verdict"], "❓") for rv in round_verdicts)
                            with print_lock:
                                sc = active_scans[0]
                                at = active_triages[0]
                                ts = datetime.now().strftime("%H:%M:%S")
                                short_t = t_title[:35] + "..." if len(t_title) > 35 else t_title
                                print(f"  {ts}    R{rn}/{triage_rounds} {history} {t_short}: {short_t}  [LLMs running S:{sc} T:{at}]")

                        if prior is None:
                            prior = []

                        reasoning_text = tv.get("reasoning", "")

                        # Execute any GREP requests from this round
                        grep_results = execute_grep_requests(reasoning_text, repo_dir)
                        if grep_results:
                            tv["grep_used"] = True
                            tv["grep_results"] = grep_results

                        # Condense grep results from older rounds to save
                        # context while preserving key evidence for later rounds
                        if prior:
                            prior = [(v, _condense_prior_greps(r))
                                     for v, r in prior]

                        reasoning_with_greps = reasoning_text
                        if grep_results:
                            reasoning_with_greps += (
                                f"\n\n[GREP RESULTS]:\n{grep_results}"
                            )
                        prior.append((tv["verdict"], reasoning_with_greps))

                    n_valid = sum(1 for rv in round_verdicts if rv["verdict"] == "VALID")
                    n_invalid = sum(1 for rv in round_verdicts if rv["verdict"] == "INVALID")
                    n_total = len(round_verdicts)
                    any_greps = any(rv.get("grep_used") for rv in round_verdicts)
                    confidence = n_valid / n_total if n_total > 0 else 0
                    verdicts_str = "".join(rv["verdict"][0] for rv in round_verdicts)

                    # Final arbiter: fresh call with just the key facts
                    if triage_rounds > 1:
                        # Collect reasoning summaries and grep results
                        evidence = []
                        for rv in round_verdicts:
                            rv_emoji = VERDICT_EMOJI.get(rv["verdict"], "?")
                            reasoning = rv.get("reasoning", "")
                            # Include first ~500 chars of reasoning + crux
                            summary = reasoning[:500]
                            if len(reasoning) > 500:
                                summary += "..."
                            crux_m = re.search(r'CRUX:\s*(.+?)(?:\n|$)', reasoning)
                            crux = f"\nCRUX: {crux_m.group(1).strip()}" if crux_m else ""
                            evidence.append(
                                f"**Round {rv.get('round', '?')} ({rv_emoji} {rv['verdict']}):** "
                                f"{summary}{crux}"
                            )
                            if rv.get("grep_results"):
                                evidence.append(rv["grep_results"])

                        arbiter_prompt = (
                            f"A vulnerability was reported in {project_name}:\n"
                            f"{t_title}\n\n"
                            f"The reported finding:\n{t_text}\n\n"
                            f"Key evidence from {n_total} rounds of analysis:\n"
                            + "\n".join(evidence[:10]) + "\n\n"
                            f"Verdicts so far: {verdicts_str} "
                            f"({n_valid} valid, {n_invalid} invalid)\n\n"
                            f"The relevant source code from {t_display}:\n"
                            f"```c\n{t_code}\n```\n\n"
                            "Based on the code and evidence, is this a "
                            "real security vulnerability? Verify any "
                            "numeric values yourself from the code.\n\n"
                            + (f"NOTE: All {n_total} prior reviewers said "
                               "UNCERTAIN or INVALID. Only override to VALID "
                               "if the evidence is overwhelming and you can "
                               "justify it clearly.\n\n"
                               if n_valid == 0 else "") +
                            "Respond with JSON: "
                            '{"verdict": "VALID/INVALID", '
                            '"reasoning": "concise explanation"}'
                        )
                        try:
                            with triage_semaphore:
                                with print_lock:
                                    active_triages[0] += 1
                                try:
                                    arbiter_resp, _, _ = call_llm(
                                        args.model,
                                        [{"role": "system",
                                          "content": "You are an impartial judge. "
                                          "Decide based on evidence, not arguments."},
                                         {"role": "user", "content": arbiter_prompt}],
                                        keys, json_mode=True,
                                    )
                                finally:
                                    with print_lock:
                                        active_triages[0] -= 1

                            arbiter_parsed = _extract_json(arbiter_resp)
                            if isinstance(arbiter_parsed, dict):
                                arbiter_verdict = arbiter_parsed.get(
                                    "verdict", "").upper()
                                if arbiter_verdict in ("VALID", "INVALID"):
                                    round_verdicts.append({
                                        "verdict": arbiter_verdict,
                                        "reasoning": f"[ARBITER] {arbiter_parsed.get('reasoning', '')}",
                                        "round": n_total + 1,
                                        "file": t_display,
                                        "finding_title": t_title,
                                    })
                                    verdicts_str += "→" + arbiter_verdict[0]
                                    if arbiter_verdict == "VALID":
                                        n_valid += 1
                                    else:
                                        n_invalid += 1
                                    n_total += 1
                                    confidence = n_valid / n_total
                        except Exception:
                            pass  # arbiter failure is non-fatal

                    final_tv = round_verdicts[-1].copy()
                    final_tv["all_rounds"] = round_verdicts
                    final_tv["confidence"] = round(confidence, 2)
                    final_tv["verdicts_str"] = verdicts_str
                    final_tv["verdict"] = round_verdicts[-1]["verdict"]

                    short_title = final_tv["finding_title"]
                    if len(short_title) > 45:
                        short_title = short_title[:42] + "..."
                    emoji = VERDICT_EMOJI.get(final_tv["verdict"], "❓")
                    conf_pct = int(confidence * 100)

                    # Write triage detail file
                    triage_dir = os.path.join(out_dir, "triages")
                    os.makedirs(triage_dir, exist_ok=True)
                    safe_file = t_display.replace("/", "_").replace("\\", "_")
                    safe_title = re.sub(r'[^\w\-]', '_', final_tv["finding_title"][:40]).strip("_")

                    with print_lock:
                        triage_counter[0] += 1
                        tc = triage_counter[0]
                        tt = triage_total[0]

                    triage_md = os.path.join(triage_dir, f"T{tc:04d}_{safe_file}_{safe_title}.md")
                    with open(triage_md, "w") as tf:
                        tf.write(f"# Triage T{tc:04d}: {final_tv['finding_title']}\n\n")
                        tf.write(f"- **File**: `{t_display}`\n")
                        tf.write(f"- **Verdict**: {final_tv['verdict']}\n")
                        tf.write(f"- **Confidence**: {conf_pct}% [{verdicts_str}]\n\n")
                        tf.write("---\n\n## Finding\n\n")
                        tf.write(final_tv.get("finding_title", ""))
                        tf.write("\n\n---\n\n## Triage rounds\n\n")
                        for rv in round_verdicts:
                            rv_emoji = VERDICT_EMOJI.get(rv["verdict"], "❓")
                            tf.write(f"### Round {rv['round']}: {rv_emoji} {rv['verdict']}\n\n")
                            reasoning = rv.get("reasoning", "")
                            # Extract and highlight crux
                            crux_match = re.search(r'CRUX:\s*(.+?)(?:\n|$)', reasoning)
                            if crux_match:
                                tf.write(f"**🎯 Crux:** {crux_match.group(1).strip()}\n\n")
                            tf.write(reasoning)
                            if rv.get("grep_results"):
                                tf.write(f"\n\n🔎 **Grep results:**\n\n{rv['grep_results']}")
                            tf.write("\n\n")

                    final_tv["triage_md"] = triage_md

                    with print_lock:
                        sc = active_scans[0]
                        at = active_triages[0]
                        ts = datetime.now().strftime("%H:%M:%S")
                        load = f"[LLMs running S:{sc} T:{at}]"
                        grep_icon = " 🔎" if any_greps else ""
                        if triage_rounds > 1:
                            print(f"  {ts} 🔬 [triage {tc}/{tt}] {emoji} {conf_pct}% [{verdicts_str}]{grep_icon} {t_short}: {short_title}  {load}")
                        else:
                            print(f"  {ts} 🔬 [triage {tc}/{tt}] {emoji}{grep_icon} {t_short}: {short_title}  {load}")
                        print(f"         📄 {triage_md}")

                        if final_tv["verdict"] == "VALID":
                            triage_valid_count[0] += 1
                        elif final_tv["verdict"] == "INVALID":
                            triage_invalid_count[0] += 1
                        else:
                            triage_uncertain_count[0] += 1

                        _show_every = 25 if tt > 100 else 10
                        if tc > 1 and tc % _show_every == 0:
                            _el = time.time() - scan_start
                            _v = triage_valid_count[0]
                            _i = triage_invalid_count[0]
                            _u = triage_uncertain_count[0]
                            _rate = tc / _el * 60 if _el > 0 else 0
                            print(f"\n  {'─' * 58}")
                            print(f"  📊 Triage: triage {tc}/{tt} done  ⏱️ {_el:.0f}s  ({_rate:.1f}/min)")
                            print(f"     ✅ {_v} valid   ❌ {_i} rejected   ❓ {_u} uncertain")
                            print(f"  {'─' * 58}\n")

                    all_triage_results.append(final_tv)

                for fi, (title, text) in enumerate(to_triage):
                    with print_lock:
                        triage_total[0] += 1
                    triage_executor.submit(
                        _triage_one_finding, title, text, code,
                        display_name, short_name,
                    )

        return result

    max_conn = args.max_connections or (args.parallel + args.triage_parallel)
    triage_executor = ThreadPoolExecutor(max_workers=max_conn) if do_triage else None

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {executor.submit(process_file, fi): fi for fi in scannable}
        for future in as_completed(futures):
            results.append(future.result())

    # Scans done — release scan capacity into the triage semaphore so
    # triage can use all available connections.
    if triage_executor:
        if triage_semaphore:
            for _ in range(args.parallel):
                triage_semaphore.release()
        remaining = triage_total[0] - triage_counter[0]
        if remaining > 0:
            max_conn = args.max_connections or (args.parallel + args.triage_parallel)
            print(f"\n⏳ Scans complete. {remaining} triages remaining (full capacity: {max_conn} connections)...")
        triage_executor.shutdown(wait=True)

    wall_time = time.time() - scan_start

    # Sort results by severity for summary
    results.sort(key=lambda r: (
        -r["severities"].get("critical", 0),
        -r["severities"].get("high", 0),
        -r["severities"].get("medium", 0),
    ))

    # Summary
    crit_files = [r for r in results if r["severities"].get("critical", 0) > 0]
    high_files = [r for r in results if r["severities"].get("high", 0) > 0 and r not in crit_files]
    med_files = [r for r in results if r["severities"].get("medium", 0) > 0 and r not in crit_files and r not in high_files]
    clean_files = [r for r in results if sum(r["severities"].values()) == 0 and r["status"] == "ok"]
    error_files = [r for r in results if r["status"] == "error"]

    print()
    print("━" * 60)
    print(f"📊 Summary: {len(results)} files scanned in {wall_time:.0f}s")
    if crit_files:
        crit_total = sum(r["severities"]["critical"] for r in crit_files)
        print(f"   🔴 Critical: {len(crit_files)} files ({crit_total} findings)")
        for r in crit_files:
            print(f"      → {r['display_name']}")
    if high_files:
        high_total = sum(r["severities"]["high"] for r in high_files)
        print(f"   🟠 High:     {len(high_files)} files ({high_total} findings)")
    if med_files:
        print(f"   🟡 Medium:   {len(med_files)} files")
    print(f"   🟢 Clean:    {len(clean_files)} files")
    if error_files:
        print(f"   ❌ Errors:   {len(error_files)} files")
    print(f"💾 Results saved to: {out_dir}/")

    # Triage summary
    if all_triage_results:
        valid_count = sum(1 for t in all_triage_results if t["verdict"] == "VALID")
        invalid_count = sum(1 for t in all_triage_results if t["verdict"] == "INVALID")
        uncertain_count = sum(1 for t in all_triage_results if t["verdict"] == "UNCERTAIN")

        print()
        print(f"🔬 Triage: ✅ {valid_count} valid | ❌ {invalid_count} rejected | ❓ {uncertain_count} uncertain")

        if valid_count > 0:
            print()
            survivors = sorted(
                [t for t in all_triage_results if t["verdict"] == "VALID"],
                key=lambda t: -t.get("confidence", 1),
            )
            min_conf = args.min_confidence
            if min_conf > 0:
                survivors = [t for t in survivors if t.get("confidence", 1) >= min_conf]

            if survivors:
                print("   🚨 Findings that survived triage:")
            else:
                print("   🟢 No findings above confidence threshold.")

            findings_dir = os.path.join(out_dir, "findings")
            os.makedirs(findings_dir, exist_ok=True)

            for idx, t in enumerate(survivors, 1):
                safename = t["file"].replace("/", "_").replace("\\", "_")
                conf = t.get("confidence", 1)
                conf_pct = int(conf * 100)

                if conf >= 0.9:
                    bar = "🔥"
                elif conf >= 0.7:
                    bar = "✅"
                elif conf >= 0.5:
                    bar = "🤔"
                else:
                    bar = "❓"

                finding_filename = f"VULN-{idx:03d}_{safename}.md"
                finding_path = os.path.join(findings_dir, finding_filename)

                with open(finding_path, "w") as ff:
                    ff.write(f"# VULN-{idx:03d}: {t['finding_title']}\n\n")
                    ff.write(f"- **File**: `{t['file']}`\n")
                    ff.write(f"- **Confidence**: {conf_pct}%")
                    vs = t.get("verdicts_str", "")
                    if vs:
                        ff.write(f" [{vs}]")
                    ff.write("\n")
                    ff.write(f"- **Project**: {project_name}\n")
                    ff.write(f"- **Date**: {timestamp}\n\n")
                    ff.write("---\n\n")
                    ff.write("## Scanner finding\n\n")
                    all_rounds = t.get("all_rounds", [])
                    if all_rounds:
                        ff.write(all_rounds[0].get("finding_title", ""))
                        ff.write("\n\n")
                        body = next(
                            (f["body"] for f in parse_findings(
                                next((r["report"] for r in results
                                      if r.get("display_name") == t["file"]),
                                     ""))
                             if f["title"] in t["finding_title"]
                             or t["finding_title"] in f["title"]),
                            None,
                        )
                        if body:
                            ff.write(body)
                            ff.write("\n\n")
                    ff.write("---\n\n")
                    ff.write("## Triage reasoning\n\n")
                    for ri, rv in enumerate(all_rounds, 1):
                        emoji = VERDICT_EMOJI.get(rv["verdict"], "❓")
                        ff.write(f"### Round {ri}: {emoji} {rv['verdict']}\n\n")
                        ff.write(rv.get("reasoning", ""))
                        ff.write("\n\n")

                vs = t.get("verdicts_str", "")
                arbiter_str = ""
                if "→" in vs:
                    arbiter_v = vs.split("→")[-1]
                    arbiter_emoji = {"V": "✅", "I": "❌"}.get(arbiter_v, "❓")
                    arbiter_str = f" (arbiter: {arbiter_emoji})"
                print(f"      {bar} {conf_pct}% [{vs}]{arbiter_str} {t['file']}: {t['finding_title']}")
                print(f"         📄 {finding_path}")

        with open(os.path.join(out_dir, "triage.json"), "w") as f:
            json.dump(all_triage_results, f, indent=2)

        triage_md_path = os.path.join(out_dir, "triage_survivors.md")
        with open(triage_md_path, "w") as f:
            f.write(f"# nano-analyzer triage survivors\n\n")
            f.write(f"- **Target**: `{os.path.abspath(args.path)}`\n")
            f.write(f"- **Date**: {timestamp}\n")
            f.write(f"- **Model**: {args.model}\n")
            f.write(f"- **Threshold**: {triage_threshold}+\n")
            f.write(f"- **Results**: ✅ {valid_count} valid | "
                    f"❌ {invalid_count} rejected | "
                    f"❓ {uncertain_count} uncertain\n\n")
            f.write("---\n\n")
            for t in all_triage_results:
                if t["verdict"] != "VALID":
                    continue
                f.write(f"## ✅ {t['file']}: {t['finding_title']}\n\n")
                f.write(f"**Verdict**: VALID\n\n")
                f.write(f"### Triage reasoning\n\n")
                f.write(t["reasoning"])
                f.write("\n\n---\n\n")

        print(f"\n   📄 Triage writeup: {triage_md_path}")

    # Save summary
    summary = {
        "timestamp": timestamp,
        "target": os.path.abspath(args.path),
        "model": args.model,
        "files_scanned": len(results),
        "total_lines": total_lines,
        "wall_time_seconds": round(wall_time, 1),
        "files_skipped": len(skipped),
        "critical_files": len(crit_files),
        "high_files": len(high_files),
        "clean_files": len(clean_files),
        "error_files": len(error_files),
        "per_file": [
            {
                "file": r["display_name"],
                "lines": r.get("lines", 0),
                "severities": r["severities"],
                "status": r["status"],
                "elapsed": r.get("total_elapsed", 0),
            }
            for r in results
        ],
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Human-readable summary
    with open(os.path.join(out_dir, "summary.md"), "w") as f:
        f.write(f"# nano-analyzer scan results\n\n")
        f.write(f"- **Target**: `{os.path.abspath(args.path)}`\n")
        f.write(f"- **Date**: {timestamp}\n")
        f.write(f"- **Model**: {args.model}\n")
        f.write(f"- **Files scanned**: {len(results)} ({total_lines:,} lines)\n")
        f.write(f"- **Wall time**: {wall_time:.0f}s\n\n")
        f.write("| File | Lines | Critical | High | Medium | Low |\n")
        f.write("|------|-------|----------|------|--------|-----|\n")
        for r in results:
            s = r["severities"]
            f.write(f"| {r['display_name']} | {r.get('lines',0)} "
                    f"| {s.get('critical',0)} | {s.get('high',0)} "
                    f"| {s.get('medium',0)} | {s.get('low',0)} |\n")

    print()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="nano-analyzer",
        description="🔍 nano-analyzer: Minimal LLM-powered zero-day vulnerability scanner by AISLE",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Model for all stages (default: {DEFAULT_MODEL})")
    parser.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL,
                        help=f"Max concurrent scan calls (default: {DEFAULT_PARALLEL})")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                        help=f"Skip files larger than this (default: {DEFAULT_MAX_CHARS:,})")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (default: ~/nano-analyzer-results/<timestamp>/)")
    parser.add_argument("--triage-threshold", default="medium",
                        choices=SEVERITY_LEVELS[:4],
                        help="Triage findings at or above this severity (default: medium)")
    parser.add_argument("--triage-rounds", type=int, default=5,
                        help="Triage rounds per finding (default: 5)")
    parser.add_argument("--triage-parallel", type=int, default=50,
                        help="Max concurrent triage calls (default: 50)")
    parser.add_argument("--max-connections", type=int, default=None,
                        help="Max total concurrent API calls (default: parallel + triage-parallel)")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                        help="Only show findings above this confidence threshold, "
                             "e.g. 0.7 for 70%% (default: 0, show all)")
    parser.add_argument("--project", default=None,
                        help="Project name for triage prompt (default: directory name)")
    parser.add_argument("--repo-dir", default=None,
                        help="Root of the full repo for triage grep lookups "
                             "(default: parent dir for files, scan dir for folders)")
    parser.add_argument("--verbose-triage", action="store_true",
                        help="Show per-round triage progress")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"❌ Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    run_scan(args)


if __name__ == "__main__":
    main()
