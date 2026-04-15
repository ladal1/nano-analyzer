# Nano-analyzer

**A minimal LLM-powered zero-day vulnerability scanner by [AISLE](https://aisle.com).**

![aisle-nano-analyzer-diagram](aisle-nano-analyzer.png)

> **Research prototype for demonstration purposes.** This is a simple, single-file harness that is able to detect real zero-day vulnerabilities. Note that it is a prototype, biased towards C/C++ memory safety bugs, and will produce false positives. We are sharing it as-is in the spirit of open research — expect sharp corners.

## What it does

Nano-analyzer is a simple single-file Python scanner that sends source code through a three-stage LLM pipeline:

1. **Context generation** — a model writes a security briefing about the file: what it does, where untrusted data flows, which buffers exist and how big they are.
2. **Vulnerability scan** — the same model, primed with the context, hunts for zero-day bugs function by function and outputs structured findings.
3. **Skeptical triage** — each finding is challenged over multiple rounds by a skeptical reviewer that can grep the codebase to verify (or refute) defenses. An arbiter makes the final call.

Results are saved as Markdown and JSON files for human review.

## Current limitations

This is a v0.1 prototype. Please keep the following in mind:

- **C/C++ bias.** The prompts, few-shot examples, and heuristics are heavily tuned for C/C++ memory safety vulnerabilities (buffer overflows, NULL derefs, integer overflows, type confusion). It will scan other languages but is much less effective there.
- **False positives.** Even with multi-round triage, expect findings that don't hold up on closer inspection. Always verify manually.
- **False negatives.** The scanner can miss entire vulnerability classes — logic bugs, race conditions, cryptographic issues, authentication bypasses, etc. A clean scan does not mean the code is safe.
- **Single-file analysis.** Each file is scanned independently. Cross-file vulnerabilities that depend on interactions between compilation units will likely be missed.
- **LLM-dependent.** Results vary with the model used. Different models will find different things and hallucinate different false positives.

## Setup

### Requirements

- Python 3.8+
- An OpenAI API key (for OpenAI models) or an OpenRouter API key (for other providers)
- Optional: [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`) for triage grep lookups
- Optional: [Google codesearch](https://github.com/google/codesearch) (`csearch`/`cindex`) for faster grep on large repos

### Install

```bash
git clone https://github.com/weareaisle/nano-analyzer.git
cd nano-analyzer
# No dependency installation needed. Run directly:
python3 scan.py --help
```

### API keys

Set your API key as an environment variable:

```bash
# For OpenAI models (model names without a slash, e.g. "gpt-5.4-nano"):
export OPENAI_API_KEY=sk-...

# For OpenRouter models (model names with a slash, e.g. "qwen/qwen3-32b"):
export OPENROUTER_API_KEY=sk-or-...
```

The scanner determines which key to use based on the model name: if it contains a `/`, it routes through OpenRouter; otherwise it uses the OpenAI API directly.

### Endpoint overrides (OpenAI-compatible)

By default, nano-analyzer uses:

- OpenAI: `https://api.openai.com/v1/chat/completions`
- OpenRouter: `https://openrouter.ai/api/v1/chat/completions`

You can override either endpoint with environment variables:

```bash
# Override OpenAI endpoint (must be OpenAI-compatible chat/completions API)
export OPENAI_API_URL=https://your-openai-compatible-host/v1/chat/completions

# Override OpenRouter endpoint
export OPENROUTER_API_URL=https://your-openrouter-compatible-host/v1/chat/completions
```

This is useful for proxies, gateways, self-hosted OpenAI-compatible providers, or enterprise routing layers.

## Usage

### Basic scan

```bash
# Scan a single file
python3 scan.py ./path/to/file.c

# Scan a directory recursively
python3 scan.py ./path/to/src/
```

### Common options

```bash
# Use a different model
python3 scan.py ./src --model gpt-5.4

# Control parallelism
python3 scan.py ./src --parallel 30

# Point triage grep at the full repo root (useful when scanning a subdirectory)
python3 scan.py ./lib/crypto/ --repo-dir ./

# Only surface high-confidence findings
python3 scan.py ./src --min-confidence 0.7

# More triage rounds for higher accuracy (default: 5)
python3 scan.py ./src --triage-rounds 7
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `path` | *(required)* | File or directory to scan |
| `--model` | `gpt-5.4-nano` | Model for all stages (context, scan, triage) |
| `--parallel` | `50` | Max concurrent scan API calls |
| `--triage-threshold` | `medium` | Triage findings at or above this severity |
| `--triage-rounds` | `5` | Triage rounds per finding |
| `--triage-parallel` | `50` | Max concurrent triage API calls |
| `--max-connections` | `parallel + triage-parallel` | Total API call cap |
| `--min-confidence` | `0.0` | Only show findings above this confidence (0.0–1.0) |
| `--project` | directory name | Project name used in triage prompts |
| `--repo-dir` | auto | Repo root for grep lookups (auto: parent dir for files, scan dir for folders) |
| `--output-dir` | `~/nano-analyzer-results/<timestamp>/` | Where to save results |
| `--max-chars` | `200,000` | Skip files larger than this |
| `--verbose-triage` | off | Show per-round triage progress |

## Output

Results are saved to `~/nano-analyzer-results/<timestamp>/` (or `--output-dir`):

```
<timestamp>/
├── summary.json              # machine-readable scan summary
├── summary.md                # human-readable scan summary
├── <filename>.md             # raw scanner output per file
├── <filename>.context.md     # context briefing per file
├── <filename>.json           # full result data per file
├── triages/                  # detailed triage reasoning
│   └── T0001_<file>_<title>.md
├── findings/                 # findings that survived triage
│   └── VULN-001_<file>.md
├── triage.json               # all triage verdicts
└── triage_survivors.md       # summary of validated findings
```

## How triage works

When a scan finds a medium-or-above severity issue, the triage pipeline kicks in:

1. A skeptical reviewer examines the finding against the actual code and can **grep the codebase** to verify or refute claimed defenses.
2. This repeats for multiple rounds (default: 5), with each reviewer seeing prior arguments and encouraged to find *new* evidence rather than rehash old points.
3. A final **arbiter** reads all rounds and makes a VALID/INVALID call.
4. The confidence score (e.g. 80% \[VVIVV→V\]) reflects the fraction of rounds that said VALID.

Findings that survive triage are written to the `findings/` directory with full reasoning chains.

## Disclaimer

This tool is a research prototype. It is not a replacement for professional security audits, manual code review, or established static analysis tools. Do not rely on it as your sole security assessment. Use at your own risk.

## License

Apache License 2.0
