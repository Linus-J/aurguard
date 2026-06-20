#!/usr/bin/env bash
# aurguard - AUR pre-install security hook
# Run via a wrapper around your AUR helper (paru/yay) or as a standalone check
# Usage: aurguard <package_name>  OR  source and call aurguard_check
#
# Checks (deterministic, no LLM):
#   1. Maintainer/ownership change detection
#   2. New dependency additions (makedepends + depends)
#   3. PKGBUILD IOC scan (dangerous downloaders, suspicious executors)
#   4. Orphan status flag
#   5. Checksum presence enforcement
#   6. Optional: Ollama LLM narrative summary
#
# Requirements: curl, jq, git, [ollama - optional]
# Install: add `aurguard <pkgname>` before your AUR helper install line,
#          or use the paru/yay wrapper below.

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────────
AURGUARD_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/aurguard"
CACHE_DIR="$AURGUARD_DIR/cache"
LOG_FILE="$AURGUARD_DIR/audit.log"
OLLAMA_ENABLED="${AURGUARD_OLLAMA:-1}"          # set AURGUARD_OLLAMA=0 to disable
OLLAMA_MODEL="${AURGUARD_MODEL:-qwen2.5-coder}" # or whatever you have pulled
OLLAMA_URL="${AURGUARD_OLLAMA_URL:-http://localhost:11434}"
AUTO_ABORT="${AURGUARD_AUTO_ABORT:-1}"          # 0 = warn only; 1 = block on HIGH findings
DAYS_LOOKBACK="${AURGUARD_DAYS:-30}"            # flag ownership changes within N days
RULES_DIR="${AURGUARD_RULES_DIR:-$AURGUARD_DIR/rules}"
AURGUARD_NONINTERACTIVE="${AURGUARD_NONINTERACTIVE:-0}"

# IOCs - extend as new campaigns emerge
DEFAULT_DANGEROUS_PATTERNS=(
    'npm install'
    'bun install'
    'pip install'
    'curl.*\|.*sh'
    'curl.*\|.*bash'
    'wget.*\|.*sh'
    'wget.*\|.*bash'
    'eval.*curl'
    'eval.*wget'
    'atomic-lockfile'
    'js-digest'
    'base64 -d'
    'base64 --decode'
    'exec.*\/tmp\/'
    'chmod.*\+x.*\/tmp\/'
    '\/dev\/tcp\/'
    'nc -e'
    'ncat.*-e'
    'mkfifo.*\/tmp\/'
    'python.*-c.*import'
    'python3.*-c.*import'
    'preinstall'
)

# Suspicious binary execution patterns in install hooks
DEFAULT_HOOK_EXEC_PATTERNS=(
    'src/hooks/'        # hook directories
    '\./deps'          # the specific atomic-lockfile payload name
)

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ────────────────────────────────────────────────────────────────────
log() { echo "$(date -Iseconds) [$1] $2" >> "$LOG_FILE"; }
info()  { echo -e "${CYAN}[aurguard]${RESET} $*" >&2; }
warn()  { echo -e "${YELLOW}[aurguard][WARN]${RESET} $*" >&2; log "WARN" "$*"; }
alert() { echo -e "${RED}${BOLD}[aurguard][HIGH]${RESET} $*" >&2; log "HIGH" "$*"; }
ok()    { echo -e "${GREEN}[aurguard][OK]${RESET} $*" >&2; }

print_banner() {
    local text="$1"
    local total_width=41
    local inner_width=$((total_width - 2))
    local text_width=${#text}
    local left_padding=$(( (inner_width - text_width) / 2 ))
    local right_padding=$(( inner_width - text_width - left_padding ))
    local top_border='╔═══════════════════════════════════════╗'
    local bottom_border='╚═══════════════════════════════════════╝'

    printf '%b%s%b\n' "$BOLD$CYAN" "$top_border" "$RESET"
    printf '%b║%*s%b%*s║%b\n' "$BOLD$CYAN" "$left_padding" '' "$text" "$right_padding" '' "$RESET"
    printf '%b%s%b\n' "$BOLD$CYAN" "$bottom_border" "$RESET"
}

die() {
    alert "Aborting install of ${PKG}: $*"
    echo ""
    echo -e "${BOLD}  Review PKGBUILD manually:${RESET}"
    echo -e "  https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=${PKG}"
    echo -e "  https://aur.archlinux.org/packages/${PKG}"
    echo ""
    exit 2
}

aur_api() {
    curl -fsSL "https://aur.archlinux.org/rpc/v5/$*"
}

record_finding() {
    local level="$1"
    local finding="$2"

    FINDINGS+=("$finding")
    case "$level" in
        HIGH) RISK_LEVEL="HIGH" ;;
        MEDIUM) [[ "$RISK_LEVEL" != "HIGH" ]] && RISK_LEVEL="MEDIUM" ;;
    esac
}

load_rule_list() {
    local rule_file="$1"
    local -n target_array="$2"

    target_array=()
    while IFS= read -r pattern; do
        [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
        target_array+=("$pattern")
    done < "$rule_file"
}

load_rules() {
    local dangerous_file="$RULES_DIR/dangerous.patterns"
    local hook_file="$RULES_DIR/hook_exec.patterns"

    if [[ -f "$dangerous_file" ]]; then
        load_rule_list "$dangerous_file" DANGEROUS_PATTERNS
    else
        DANGEROUS_PATTERNS=("${DEFAULT_DANGEROUS_PATTERNS[@]}")
    fi

    if [[ -f "$hook_file" ]]; then
        load_rule_list "$hook_file" HOOK_EXEC_PATTERNS
    else
        HOOK_EXEC_PATTERNS=("${DEFAULT_HOOK_EXEC_PATTERNS[@]}")
    fi
}

extract_json_payload() {
    local raw_text="$1"
    local json_text

    json_text=$(sed -n '/{/,/}/p' <<< "$raw_text")
    if jq -e . >/dev/null 2>&1 <<< "$json_text"; then
        printf '%s' "$json_text"
        return 0
    fi

    if jq -e . >/dev/null 2>&1 <<< "$raw_text"; then
        printf '%s' "$raw_text"
        return 0
    fi

    return 1
}

scan_file_for_patterns() {
    local scan_file="$1"
    local fname
    fname=$(basename "$scan_file")

    info "Scanning ${fname}..."

    local pattern matched=0
    for pattern in "${DANGEROUS_PATTERNS[@]}"; do
        if grep -qiE "$pattern" "$scan_file" 2>/dev/null; then
            alert "IOC match in ${fname}: pattern '${pattern}'"
            record_finding "HIGH" "IOC_MATCH:${fname}:${pattern}"
            matched=1
            grep -inE "$pattern" "$scan_file" | head -5 | while IFS= read -r line; do
                echo -e "    ${RED}→${RESET} $line"
            done
        fi
    done

    for pattern in "${HOOK_EXEC_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$scan_file" 2>/dev/null; then
            alert "Suspicious exec pattern in ${fname}: '${pattern}'"
            record_finding "HIGH" "EXEC_PATTERN:${fname}:${pattern}"
            matched=1
            grep -nE "$pattern" "$scan_file" | head -5 | while IFS= read -r line; do
                echo -e "    ${RED}→${RESET} $line"
            done
        fi
    done

    [[ "$matched" -eq 1 ]]
}

# ── Setup ──────────────────────────────────────────────────────────────────────
setup() {
    mkdir -p "$CACHE_DIR"
    touch "$LOG_FILE"
    load_rules
}

# ── 1. Fetch package metadata from AUR RPC ────────────────────────────────────
fetch_metadata() {
    local pkg="$1"
    local cache_file="$CACHE_DIR/${pkg}.meta.json"

    info "Fetching AUR metadata for ${BOLD}${pkg}${RESET}..."
    aur_api "info?arg[]=${pkg}" > "$cache_file" 2>/dev/null || {
        warn "Could not reach AUR RPC API - skipping metadata checks"
        return 1
    }

    local result_count
    result_count=$(jq '.resultcount' "$cache_file" 2>/dev/null || echo 0)
    if [[ "$result_count" -eq 0 ]]; then
        warn "Package '${pkg}' not found on AUR - may be a repo package"
        return 1
    fi
    echo "$cache_file"
}

# ── 2. Ownership / maintainer change check ────────────────────────────────────
check_maintainer() {
    local meta_file="$1"
    local prev_file="$CACHE_DIR/${PKG}.meta.prev.json"

    local maintainer orphan_since last_modified
    maintainer=$(jq -r '.results[0].Maintainer // "null"' "$meta_file")
    last_modified=$(jq -r '.results[0].LastModified' "$meta_file")
    local last_mod_human
    last_mod_human=$(date -d "@${last_modified}" 2>/dev/null || date -r "$last_modified" 2>/dev/null || echo "unknown")

    # Compare against cached previous metadata
    if [[ -f "$prev_file" ]]; then
        local prev_maintainer
        prev_maintainer=$(jq -r '.results[0].Maintainer // "null"' "$prev_file")

        if [[ "$prev_maintainer" != "$maintainer" ]]; then
            # Distinguish the three transition types
            if [[ "$prev_maintainer" == "null" && "$maintainer" != "null" ]]; then
                # Orphan → adopted: the highest-risk transition (exact attack vector)
                alert "Package was ORPHANED and has been ADOPTED by: ${maintainer}"
                alert "This is the primary supply-chain attack vector - review PKGBUILD carefully"
                FINDINGS+=("UNORPHANED: null → ${maintainer} (was orphaned, now adopted - HIGH RISK)")
                RISK_LEVEL="HIGH"
            elif [[ "$prev_maintainer" != "null" && "$maintainer" == "null" ]]; then
                # Legitimate maintainer dropped it - now orphaned, watch for adoption next run
                warn "Package has become ORPHANED (previous maintainer: ${prev_maintainer})"
                FINDINGS+=("NEWLY_ORPHANED: ${prev_maintainer} → null (watch for adoption)")
                [[ "$RISK_LEVEL" != "HIGH" ]] && RISK_LEVEL="MEDIUM"
            else
                # Maintainer-to-maintainer transfer - also suspicious
                alert "Maintainer CHANGED: ${prev_maintainer} → ${maintainer}"
                FINDINGS+=("MAINTAINER_CHANGE: ${prev_maintainer} → ${maintainer}")
                RISK_LEVEL="HIGH"
            fi
        else
            # No change - but still note if currently orphaned as a soft warning
            if [[ "$maintainer" == "null" ]]; then
                warn "Package is orphaned (no maintainer) - unchanged since last check"
                FINDINGS+=("ORPHANED: No maintainer (stable, but watch for adoption)")
                [[ "$RISK_LEVEL" != "HIGH" ]] && RISK_LEVEL="MEDIUM"
            else
                ok "Maintainer unchanged: ${maintainer}"
            fi
        fi
    else
        info "No previous metadata cached - storing baseline for ${PKG}"
        # First-seen: check if last modification was very recent
        local now cutoff
        now=$(date +%s)
        cutoff=$((now - DAYS_LOOKBACK * 86400))
        if [[ "$last_modified" -gt "$cutoff" ]]; then
            info "Package was last modified recently (${last_mod_human}) - first time seeing this package"
        fi
    fi

    # Save current as new baseline (after install, only if user proceeds)
    cp "$meta_file" "${CACHE_DIR}/${PKG}.meta.pending.json"
}

# ── 2b. AUR out-of-date check ─────────────────────────────────────────────────
check_out_of_date() {
    local meta_file="$1"

    local out_of_date
    out_of_date=$(jq -r '.results[0].OutOfDate // null' "$meta_file" 2>/dev/null || echo "null")

    if [[ "$out_of_date" != "null" ]]; then
        info "Package is flagged OUT OF DATE on AUR"
        FINDINGS+=("OUT_OF_DATE: AUR package is flagged out of date (informational)")
    fi
}

# ── 3. Dependency diff ────────────────────────────────────────────────────────
check_deps() {
    local meta_file="$1"
    local prev_file="$CACHE_DIR/${PKG}.meta.prev.json"

    if [[ ! -f "$prev_file" ]]; then
        info "No dep baseline - skipping dep diff (will baseline now)"
        return
    fi

    # Extract sorted dep lists
    local cur_deps prev_deps new_deps removed_deps
    cur_deps=$(jq -r '(.results[0].Depends // []) + (.results[0].MakeDepends // []) | sort[]' "$meta_file")
    prev_deps=$(jq -r '(.results[0].Depends // []) + (.results[0].MakeDepends // []) | sort[]' "$prev_file")

    new_deps=$(comm -13 <(echo "$prev_deps") <(echo "$cur_deps") || true)
    removed_deps=$(comm -23 <(echo "$prev_deps") <(echo "$cur_deps") || true)

    if [[ -n "$new_deps" ]]; then
        warn "NEW dependencies added since last check:"
        while IFS= read -r dep; do
            warn "  + ${dep}"
            FINDINGS+=("NEW_DEP: ${dep}")
            # Flag npm/node/bun/python new deps as high risk
            if echo "$dep" | grep -qiE '(nodejs|npm|bun|python|ruby|perl)'; then
                alert "  → Runtime environment dep added (${dep}) - elevated risk"
                RISK_LEVEL="HIGH"
            elif [[ "$RISK_LEVEL" != "HIGH" ]]; then
                RISK_LEVEL="MEDIUM"
            fi
        done <<< "$new_deps"
    else
        ok "No new dependencies"
    fi

    if [[ -n "$removed_deps" ]]; then
        info "Removed dependencies (informational):"
        while IFS= read -r dep; do
            info "  - ${dep}"
        done <<< "$removed_deps"
    fi
}

# ── 4. Clone & scan PKGBUILD ─────────────────────────────────────────────────
fetch_and_scan_pkgbuild() {
    local pkg="$1"
    local clone_dir="$CACHE_DIR/${pkg}.git"

    info "Cloning AUR repo for PKGBUILD analysis..."

    # Clone or pull
    if [[ -d "$clone_dir" ]]; then
        git -C "$clone_dir" fetch -q origin 2>/dev/null || true
        git -C "$clone_dir" reset -q --hard origin/master 2>/dev/null || \
            git -C "$clone_dir" reset -q --hard origin/main 2>/dev/null || true
    else
        git clone -q "https://aur.archlinux.org/${pkg}.git" "$clone_dir" 2>/dev/null || {
            warn "Could not clone AUR repo for ${pkg} - skipping PKGBUILD scan"
            return
        }
    fi

    local pkgbuild="$clone_dir/PKGBUILD"
    if [[ ! -f "$pkgbuild" ]]; then
        warn "No PKGBUILD found in repo"
        return
    fi

    # Scan PKGBUILD and .install files
    local files_to_scan=("$pkgbuild")
    while IFS= read -r install_file; do
        [[ -f "$clone_dir/$install_file" ]] && files_to_scan+=("$clone_dir/$install_file")
    done < <(grep -oP "(?<=install=')[^']+" "$pkgbuild" 2>/dev/null || true)

    local hit_found=0
    for scan_file in "${files_to_scan[@]}"; do
        if scan_file_for_patterns "$scan_file"; then
            hit_found=1
        fi
    done

    [[ $hit_found -eq 0 ]] && ok "No IOC patterns matched in PKGBUILD/install files"

    # ── Checksum enforcement ───────────────────────────────────────────────────
    check_sums "$pkgbuild"

    # ── PKGBUILD diff vs previous commit ──────────────────────────────────────
    diff_pkgbuild "$clone_dir"

    # ── Optional Ollama analysis ──────────────────────────────────────────────
    if [[ "$OLLAMA_ENABLED" == "1" ]]; then
        ollama_review "$pkgbuild"
    fi
}

# ── 5. Checksum enforcement ───────────────────────────────────────────────────
check_sums() {
    local pkgbuild="$1"

    local checksum_lines checksum_vars
    checksum_lines=$(grep -E '^[[:space:]]*(md5sums|sha1sums|sha224sums|sha256sums|sha384sums|sha512sums|b2sums)[[:space:]]*=' "$pkgbuild" 2>/dev/null || true)

    if [[ -z "$checksum_lines" ]]; then
        if grep -qiE '\bSKIP\b' "$pkgbuild" 2>/dev/null; then
            warn "All source checksums are SKIP - integrity not enforced"
            record_finding "MEDIUM" "CHECKSUMS_SKIPPED: All checksums are 'SKIP'"
        else
            alert "No checksums defined in PKGBUILD - sources unverified"
            record_finding "MEDIUM" "NO_CHECKSUMS: Sources have no integrity verification"
        fi
        return
    fi

    checksum_vars=$(printf '%s\n' "$checksum_lines" | sed -E 's/^[[:space:]]*([a-z0-9_]+)[[:space:]]*=.*/\1/' | tr '\n' ' ')

    if grep -qiE '\bSKIP\b' <<< "$checksum_lines"; then
        warn "All source checksums are SKIP - integrity not enforced"
        record_finding "MEDIUM" "CHECKSUMS_SKIPPED: All checksums are 'SKIP'"
    else
        ok "Checksums present: ${checksum_vars}"
    fi
}

# ── 6. PKGBUILD diff ─────────────────────────────────────────────────────────
diff_pkgbuild() {
    local clone_dir="$1"
    local prev_commit_file="$CACHE_DIR/${PKG}.last_commit"

    local current_commit
    current_commit=$(git -C "$clone_dir" rev-parse HEAD 2>/dev/null || echo "unknown")

    if [[ -f "$prev_commit_file" ]]; then
        local prev_commit
        prev_commit=$(cat "$prev_commit_file")
        if [[ "$prev_commit" != "$current_commit" ]]; then
            warn "PKGBUILD has changed since last check (${prev_commit:0:8} → ${current_commit:0:8})"
            record_finding "MEDIUM" "PKGBUILD_CHANGED: ${prev_commit:0:8} → ${current_commit:0:8}"
            echo ""
            echo -e "${BOLD}  PKGBUILD diff:${RESET}"
            git -C "$clone_dir" diff "${prev_commit}" HEAD -- PKGBUILD 2>/dev/null \
                | head -80 \
                | sed 's/^+/\x1b[32m+\x1b[0m/; s/^-/\x1b[31m-\x1b[0m/'
            echo ""
            local commit_meta
            commit_meta=$(git -C "$clone_dir" log -1 --format='%h | %an | %cs | %s' HEAD -- PKGBUILD 2>/dev/null || echo "unknown")
            info "Latest PKGBUILD commit: ${commit_meta}"
            [[ "$RISK_LEVEL" != "HIGH" ]] && RISK_LEVEL="MEDIUM"
        else
            ok "PKGBUILD unchanged since last check (${current_commit:0:8})"
        fi
    else
        info "No previous commit recorded - baselining at ${current_commit:0:8}"
    fi

    echo "$current_commit" > "${CACHE_DIR}/${PKG}.last_commit.pending"
}

# ── 7. Optional Ollama narrative analysis ─────────────────────────────────────
ollama_review() {
    local pkgbuild="$1"
    local pkgbuild_content
    pkgbuild_content=$(cat "$pkgbuild")

    info "Sending PKGBUILD to Ollama (${OLLAMA_MODEL}) for review..."

    local prompt="You are a security analyst reviewing an Arch Linux PKGBUILD file for signs of supply-chain compromise or malicious behaviour. Return exactly one JSON object with keys verdict and summary. verdict must be one of LOW, MEDIUM, HIGH. summary must be a short sentence under 20 words. Consider: unexpected network calls or package installs (npm/bun/pip), obfuscated commands or encoded payloads, execution of binaries from unexpected paths, missing or skipped checksums, suspicious post-install hooks. PKGBUILD:\n\`\`\`\n${pkgbuild_content}\n\`\`\`"

    local response
    response=$(curl -fsSL "${OLLAMA_URL}/api/generate" \
        -H 'Content-Type: application/json' \
        -d "$(jq -n --arg model "$OLLAMA_MODEL" --arg prompt "$prompt" \
            '{model: $model, prompt: $prompt, stream: false}')" \
        2>/dev/null | jq -r '.response // "No response"') || {
        warn "Ollama unavailable - skipping LLM review"
        return
    }

    local response_json
    if ! response_json=$(extract_json_payload "$response"); then
        warn "LLM verdict unavailable - ${response}"
        FINDINGS+=("LLM_UNKNOWN: ${response} (informational)")
        log "OLLAMA" "${PKG}: UNKNOWN ${response}"
        return
    fi

    local verdict summary
    verdict=$(jq -r '.verdict // "UNKNOWN"' <<< "$response_json" 2>/dev/null || echo "UNKNOWN")
    summary=$(jq -r '.summary // empty' <<< "$response_json" 2>/dev/null || true)
    [[ -z "$summary" ]] && summary="$response"

    case "$verdict" in
        HIGH)
            warn "LLM verdict: HIGH - ${summary}"
            FINDINGS+=("LLM_HIGH: ${summary} (informational)")
            ;;
        MEDIUM)
            warn "LLM verdict: MEDIUM - ${summary}"
            FINDINGS+=("LLM_MEDIUM: ${summary} (informational)")
            ;;
        LOW)
            ok "LLM verdict: LOW - ${summary}"
            ;;
        *)
            warn "LLM verdict unavailable - ${summary}"
            FINDINGS+=("LLM_UNKNOWN: ${summary} (informational)")
            ;;
    esac

    log "OLLAMA" "${PKG}: ${verdict} ${summary}"
}

# ── 8. Commit baseline (called after user confirms install) ───────────────────
commit_baseline() {
    [[ -f "$CACHE_DIR/${PKG}.meta.pending.json" ]] && \
        mv "$CACHE_DIR/${PKG}.meta.pending.json" "$CACHE_DIR/${PKG}.meta.prev.json"
    [[ -f "$CACHE_DIR/${PKG}.last_commit.pending" ]] && \
        mv "$CACHE_DIR/${PKG}.last_commit.pending" "$CACHE_DIR/${PKG}.last_commit"
}

# ── 9. Summary & gating ──────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    printf '%b%b%b\n' "${BOLD}  aurguard summary for: ${CYAN}" "${PKG}" "${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        ok "No issues found - package appears safe to install"
    else
        echo -e "  Risk level: ${BOLD}${RISK_LEVEL}${RESET}"
        echo -e "  Findings:"
        for finding in "${FINDINGS[@]}"; do
            if [[ "$RISK_LEVEL" == "HIGH" ]]; then
                echo -e "    ${RED}•${RESET} $finding"
            else
                echo -e "    ${YELLOW}•${RESET} $finding"
            fi
        done
    fi

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

gate_install() {
    if [[ "$RISK_LEVEL" == "HIGH" && "$AUTO_ABORT" == "1" ]]; then
        echo -e "${RED}${BOLD}INSTALL BLOCKED${RESET} - HIGH risk findings detected"
        echo ""
        echo "Override with: AURGUARD_AUTO_ABORT=0 aurguard ${PKG}"
        echo "Manual review: https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=${PKG}"
        log "BLOCKED" "${PKG}: ${FINDINGS[*]}"
        return 2
    elif [[ "$RISK_LEVEL" == "HIGH" ]]; then
        if [[ "$AURGUARD_NONINTERACTIVE" == "1" ]]; then
            return 2
        fi
        echo -e "${YELLOW}${BOLD}WARNING: HIGH risk - proceeding anyway (AUTO_ABORT=0)${RESET}"
        read -rp "Continue? [y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || return 2
    elif [[ "$RISK_LEVEL" == "MEDIUM" ]]; then
        if [[ "$AURGUARD_NONINTERACTIVE" == "1" ]]; then
            return 1
        fi
        echo -e "${YELLOW}MEDIUM risk findings - review recommended${RESET}"
        read -rp "Continue with install? [Y/n] " confirm
        [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]] || return 2
    fi

    commit_baseline
    return 0
}

# ── Main ──────────────────────────────────────────────────────────────────────
aurguard_check() {
    PKG="${1:?Usage: aurguard <package_name>}"
    FINDINGS=()
    RISK_LEVEL="LOW"

    setup

    echo ""
    print_banner "aurguard pre-install check"
    echo ""

    log "START" "Checking ${PKG}"

    local meta_file
    if meta_file=$(fetch_metadata "$PKG"); then
        check_maintainer "$meta_file"
        check_out_of_date "$meta_file"
        check_deps "$meta_file"
    fi

    fetch_and_scan_pkgbuild "$PKG"
    print_summary
    gate_install
}

# ── CLI entrypoint ────────────────────────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    aurguard_check "${1:-}"
    exit $?
fi
