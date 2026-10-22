#!/bin/sh
set -eu

GKI_ROOT=$(pwd)
OWNER="XiaoFeng-Next"
REPO="$OWNER"

display_usage() {
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
    echo "  --cleanup:              Cleans up previous modifications made by the script."
    echo "  <commit-or-tag>:        Sets up or updates the XiaoFeng-Next to specified tag or commit."
    echo "  -h, --help:             Displays this usage information."
    echo "  (no args):              Sets up or updates the XiaoFeng-Next environment to the latest tagged version."
}

initialize_variables() {
    if test -d "$GKI_ROOT/common/drivers"; then
         DRIVER_DIR="$GKI_ROOT/common/drivers"
    elif test -d "$GKI_ROOT/drivers"; then
         DRIVER_DIR="$GKI_ROOT/drivers"
    else
         echo '[ERROR] "drivers/" directory not found.'
         exit 127
    fi

    DRIVER_MAKEFILE=$DRIVER_DIR/Makefile
    DRIVER_KCONFIG=$DRIVER_DIR/Kconfig
}

# Reverts modifications made by this script
perform_cleanup() {
    echo "[+] Cleaning up..."
    [ -L "$DRIVER_DIR/xiaofeng" ] && rm "$DRIVER_DIR/xiaofeng" && echo "[-] Symlink removed."
    grep -q "xiaofeng" "$DRIVER_MAKEFILE" && sed -i '/xiaofeng/d' "$DRIVER_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "drivers/xiaofeng/Kconfig" "$DRIVER_KCONFIG" && sed -i '/drivers\/xiaofeng\/Kconfig/d' "$DRIVER_KCONFIG" && echo "[-] Kconfig reverted."
    if [ -d "$GKI_ROOT/$REPO" ]; then
        rm -rf "$GKI_ROOT/$REPO" && echo "[-] $REPO directory deleted."
    fi
}

# Sets up or update XiaoFeng-Next environment
setup_xiaofeng() {
    echo "[+] Setting up $REPO..."
    test -d "$GKI_ROOT/$REPO" || git clone "https://github.com/$OWNER/$REPO" && echo "[+] Repository cloned."
    cd "$GKI_ROOT/$REPO"
    git stash && echo "[-] Stashed current changes."

    BRANCH="$(git rev-parse --abbrev-ref origin/HEAD | sed 's@^origin/@@')"
    if [ "$(git status | grep -Po 'v\d+(\.\d+)*' | head -n1)" ]; then
        git checkout $BRANCH && echo "[-] Switched to $BRANCH branch."
    fi

    git pull && echo "[+] Repository updated."
    if [ -z "${1-}" ]; then
        git checkout "$(git describe --abbrev=0 --tags)" && echo "[-] Checked out latest tag."
    else
        git checkout "$1" && echo "[-] Checked out $1." || echo "[-] Checkout default branch"
    fi
    cd "$DRIVER_DIR"
    ln -sf "$(realpath --relative-to="$DRIVER_DIR" "$GKI_ROOT/$REPO/kernel")" "xiaofeng" && echo "[+] Symlink created."

    # Add entries in Makefile and Kconfig if not already existing
    grep -q "xiaofeng" "$DRIVER_MAKEFILE" || printf "\nobj-\$(CONFIG_XFG) += xiaofeng/\n" >> "$DRIVER_MAKEFILE" && echo "[+] Modified Makefile."
    grep -q "source \"drivers/xiaofeng/Kconfig\"" "$DRIVER_KCONFIG" || sed -i "/endmenu/i\source \"drivers/xiaofeng/Kconfig\"" "$DRIVER_KCONFIG" && echo "[+] Modified Kconfig."
    echo '[+] Done.'
}

# Process command-line arguments
if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_xiaofeng
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    display_usage
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_xiaofeng "$@"
fi
