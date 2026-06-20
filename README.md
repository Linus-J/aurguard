# aurguard

A deterministic pre-install security hook for AUR packages on Arch based distros.

Built in response to the **June 2026 atomic-lockfile/js-digest AUR supply-chain attack** (~400+ packages compromised).

---

## What it checks (in order)

| Check | How | Risk gate |
|---|---|---|
| Maintainer change | AUR RPC diff vs cached baseline | HIGH |
| Orphan status | AUR RPC `.Maintainer == null` | HIGH |
| Out-of-date AUR package | AUR RPC `.OutOfDate != null` | informational |
| New dependencies added | AUR RPC dep diff vs baseline | MEDIUM/HIGH |
| IOC pattern scan | grep against 20+ patterns in PKGBUILD + `.install` | HIGH |
| Suspicious binary execution | regex for `./binary`, `src/hooks/`, etc. | HIGH |
| Missing/SKIP checksums | Source PKGBUILD vars in subshell | MEDIUM |
| PKGBUILD git diff | git log diff vs last seen commit | MEDIUM |
| Ollama LLM review (optional) | Local Ollama narrative summary | informational |

The first 7 checks are fully **deterministic** - no external services, no false positives from model hallucination. Ollama is additive on top.

---

## Install

```bash
# 1. Install dependencies
sudo pacman -S curl jq git

# 2. Install aurguard
mkdir -p ~/.local/bin
cp aurguard.sh ~/.local/bin/aurguard
chmod +x ~/.local/bin/aurguard

# 3. (Optional) Install AUR helper wrappers
cp paru-safe.sh ~/.local/bin/paru-safe
cp yay-safe.sh ~/.local/bin/yay-safe
chmod +x ~/.local/bin/paru-safe ~/.local/bin/yay-safe

# Add ~/.local/bin to PATH if not already there
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

---

## Usage

### Standalone
```bash
aurguard firefox-beta-bin
```

### With your AUR helper
```bash
# Instead of: paru -S some-aur-package
paru-safe some-aur-package

# Or yay:
yay-safe some-aur-package
```

`yay-safe` only preflights AUR candidates. If `yay` reports additional repo packages or packages not in AUR, those are still handled by `yay` itself and are not scanned by aurguard. Out-of-date AUR packages are surfaced for manual review, but they do not raise aurguard's install risk level.

### Bulk check all installed AUR packages
```bash
pacman -Qmq | xargs -I{} aurguard {}
```

---

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `AURGUARD_AUTO_ABORT` | `1` | Block install on HIGH risk (0 = warn only) |
| `AURGUARD_OLLAMA` | `1` | Enable Ollama LLM review |
| `AURGUARD_MODEL` | `qwen2.5-coder` | Ollama model to use |
| `AURGUARD_OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint |
| `AURGUARD_DAYS` | `30` | Flag ownership changes within N days |
| `AURGUARD_RULES_DIR` | `~/.local/share/aurguard/rules` | Override the IOC/hook rule files |
| `AURGUARD_NONINTERACTIVE` | `0` | Return warning/block codes without prompting |

Example - enable Ollama with your preferred model:
```bash
AURGUARD_OLLAMA=1 AURGUARD_MODEL=qwen3:8b aurguard some-package
```

Override block for a trusted package:
```bash
AURGUARD_AUTO_ABORT=0 paru-safe some-package
```

---

## How baselining works

First run: stores the current AUR metadata (maintainer, deps) and git commit hash as a baseline under `~/.local/share/aurguard/cache/`.

Subsequent runs: diffs against that baseline and alerts on any changes. The baseline is only updated **after** you confirm the install (so an aborted install leaves the old baseline intact).

On a new machine or for first-time packages, aurguard stores a baseline if there's no cached history. Freshly modified packages are noted, but they do not automatically raise the risk level.

---

## Ollama integration

Set `AURGUARD_OLLAMA=0` to disable it. Any model works but code-focused ones (qwen2.5-coder, deepseek-coder, codellama) give better results for PKGBUILD analysis. The LLM output is **informational only** - it does not affect the risk gate. The deterministic checks run first and block independently.

Prompt sent to the model asks for: unexpected network calls, obfuscated commands, binary executions from odd paths, missing checksums, suspicious post-install hooks.

---

## Log file

All findings are logged to `~/.local/share/aurguard/audit.log` with timestamps and risk levels. Useful for auditing across both machines.

---

## IOC list

The default rules live in `rules/*.patterns` and currently include patterns from the atomic-lockfile and js-digest campaigns:
- `npm install`, `bun install`, `pip install`
- `curl|sh`, `wget|bash` pipe patterns
- `base64 -d` / `base64 --decode`
- `/dev/tcp/` reverse shell
- `exec /tmp/`, `chmod +x /tmp/`
- `atomic-lockfile`, `js-digest` (named packages)
- `./deps`, `src/hooks/` (payload execution paths)
- `preinstall` hooks in package.json invocation

To add new IOCs, edit the `dangerous.patterns` and `hook_exec.patterns` files in the rules directory, or set `AURGUARD_RULES_DIR` to point at a custom rule set.

## Tests

The repository includes a small fixture-based regression script under `tests/run.sh`.

```bash
bash tests/run.sh
```

It checks that known-bad fixtures still trigger IOC and checksum findings while known-good fixtures remain clean.
