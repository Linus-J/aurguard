#!/usr/bin/env bash
# paru-safe - paru wrapper that runs aurguard checks before installing AUR packages
# Usage: paru-safe [paru args] <package>
# Drop-in replacement for `paru -S <pkg>` for AUR packages

AURGUARD="${HOME}/.local/bin/aurguard"

if [[ ! -x "$AURGUARD" ]]; then
    echo "[paru-safe] aurguard not found at $AURGUARD - running paru directly"
    exec paru "$@"
fi

# Extract packages from args (non-flag arguments, post -S/-U/-B etc.)
declare -a PKGS=()
declare -a PARU_ARGS=()
skip_next=0

for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then
        PARU_ARGS+=("$arg")
        skip_next=0
        continue
    fi
    case "$arg" in
        --asdeps|--asexplicit|--needed|--noconfirm|--noprogressbar) PARU_ARGS+=("$arg") ;;
        --config|--dbpath|--root|--cachedir|--logfile|--gpgdir)
            PARU_ARGS+=("$arg"); skip_next=1 ;;
        -*) PARU_ARGS+=("$arg") ;;
        *) PKGS+=("$arg") ;;
    esac
done

# Run aurguard on each AUR package
ABORTED=0
for pkg in "${PKGS[@]}"; do
    # Check if it's an AUR package (not in official repos)
        if ! pacman -Si "$pkg" &>/dev/null; then
        AURGUARD_NONINTERACTIVE=1 "$AURGUARD" "$pkg"
        rc=$?
        if [[ $rc -eq 2 ]]; then
            echo "[paru-safe] aurguard blocked install of: $pkg"
            ABORTED=1
        elif [[ $rc -eq 1 ]]; then
            echo "[paru-safe] aurguard warning for: $pkg"
        fi
    fi
done

if [[ $ABORTED -eq 1 ]]; then
    echo "[paru-safe] One or more packages were blocked. Aborting."
    exit 2
fi

# Proceed with paru
exec paru "${PARU_ARGS[@]}" "${PKGS[@]}"
