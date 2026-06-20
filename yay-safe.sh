#!/usr/bin/env bash
# yay-safe - yay wrapper with aurguard pre-install/pre-update checks
#
# For explicit installs (yay -S pkg):  checks before install
# For system updates (yay -Syu):       audits all pending AUR updates first,
#                                       blocks if any are HIGH risk
# Bare invocation (yay-safe):          defaults to yay-safe -Syu
#
# Usage: replace `yay` with `yay-safe` in your workflow

AURGUARD="${HOME}/.local/bin/aurguard"

if [[ $# -eq 0 ]]; then
    set -- -Syu
fi

if [[ ! -x "$AURGUARD" ]]; then
    echo "[yay-safe] aurguard not found at $AURGUARD - running yay directly"
    exec yay "$@"
fi

# ── Detect mode ───────────────────────────────────────────────────────────────
is_syu=0
is_install=0
declare -a EXPLICIT_PKGS=()

for arg in "$@"; do
    case "$arg" in
        -Syu|-Syyu|-Suy) is_syu=1 ;;
        -S) is_install=1 ;;
        # Combined flags like -Syu handled above; catch -S in combined form too
        -S*u*|-S*y*) is_syu=1 ;;
        -*) : ;;  # other flags, ignore for package detection
        *) [[ $is_install -eq 1 ]] && EXPLICIT_PKGS+=("$arg") ;;
    esac
done

# ── Explicit install: check named packages ────────────────────────────────────
if [[ ${#EXPLICIT_PKGS[@]} -gt 0 ]]; then
    ABORTED=0
    WARNED=()
    for pkg in "${EXPLICIT_PKGS[@]}"; do
        # Only run aurguard on AUR packages (not official repos)
        if ! pacman -Si "$pkg" &>/dev/null 2>&1; then
            AURGUARD_NONINTERACTIVE=1 "$AURGUARD" "$pkg"
            rc=$?
            if [[ $rc -eq 2 ]]; then
                echo "[yay-safe] aurguard blocked: $pkg"
                ABORTED=1
            elif [[ $rc -eq 1 ]]; then
                WARNED+=("$pkg")
                echo "[yay-safe] aurguard warning: $pkg"
            fi
        fi
    done
    [[ $ABORTED -eq 1 ]] && { echo "[yay-safe] Aborting due to blocked packages."; exit 2; }
    exec yay "$@"
fi

# ── System update (-Syu): audit all pending AUR updates first ─────────────────
if [[ $is_syu -eq 1 ]]; then
    echo "[yay-safe] Checking for pending AUR updates..."

    # Refresh sync databases first so the pending AUR list is based on current
    # package metadata instead of stale local sync state.
    if ! yay -Sy --noconfirm >/dev/null 2>&1; then
        echo "[yay-safe] Warning: package database refresh failed; continuing with current metadata"
    fi

    # Get list of AUR packages with available updates
    # yay -Qu --aur lists packages with updates as "pkgname oldver -> newver"
    mapfile -t PENDING < <(yay -Qu --aur 2>/dev/null | awk '{print $1}')
    mapfile -t ALL_PENDING < <(yay -Qu 2>/dev/null | awk 'NF {print $1}')

    if [[ ${#PENDING[@]} -eq 0 ]]; then
        echo "[yay-safe] No AUR updates pending - proceeding with yay -Syu"
        if [[ ${#ALL_PENDING[@]} -gt 0 ]]; then
            echo "[yay-safe] Note: yay still reports ${#ALL_PENDING[@]} total pending package(s); aurguard only preflights AUR candidates. Repo and non-AUR packages are not scanned here."
        fi
        exec yay "$@"
    fi

    echo "[yay-safe] ${#PENDING[@]} AUR package(s) have updates - running aurguard on each:"
    echo ""

    if [[ ${#ALL_PENDING[@]} -gt ${#PENDING[@]} ]]; then
        echo "[yay-safe] Note: yay reports ${#ALL_PENDING[@]} total pending package(s), but only ${#PENDING[@]} are AUR candidates reviewed by aurguard. Repo packages and non-AUR entries should be reviewed separately."
        echo ""
    fi

    BLOCKED=()
    WARNED=()

    for pkg in "${PENDING[@]}"; do
        AURGUARD_NONINTERACTIVE=1 "$AURGUARD" "$pkg"
        rc=$?
        if [[ $rc -eq 2 ]]; then
            BLOCKED+=("$pkg")
        elif [[ $rc -eq 1 ]]; then
            WARNED+=("$pkg")
        fi
    done

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  aurguard pre-update summary"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ ${#BLOCKED[@]} -gt 0 ]]; then
        echo ""
        echo "  BLOCKED (HIGH risk - will not update):"
        for pkg in "${BLOCKED[@]}"; do
            echo "    ✗ $pkg"
        done
    fi

    if [[ ${#WARNED[@]} -gt 0 ]]; then
        echo ""
        echo "  WARNED (MEDIUM risk - proceeding):"
        for pkg in "${WARNED[@]}"; do
            echo "    ⚠ $pkg"
        done
    fi

    SAFE_COUNT=$(( ${#PENDING[@]} - ${#BLOCKED[@]} - ${#WARNED[@]} ))
    echo ""
    echo "  Clean: ${SAFE_COUNT}  |  Warned: ${#WARNED[@]}  |  Blocked: ${#BLOCKED[@]}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [[ ${#BLOCKED[@]} -gt 0 ]]; then
        echo "Some packages were blocked. Options:"
        echo "  1) Run yay -Syu anyway (skipping blocked packages is not automatic - review manually)"
        echo "  2) Abort and review blocked packages first"
        echo ""
        read -rp "Proceed with yay -Syu regardless? [y/N] " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "[yay-safe] Aborted. Review blocked packages:"
            for pkg in "${BLOCKED[@]}"; do
                echo "  https://aur.archlinux.org/packages/${pkg}"
            done
            exit 2
        fi
    fi

    exec yay "$@"
fi

# ── Fallback: pass through to yay unchanged ───────────────────────────────────
exec yay "$@"
