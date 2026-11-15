#!/usr/bin/env sh
# ==============================================================================
# AllUse Universal POSIX Installer (macOS Apple Silicon/Intel & Linux x64/ARM64)
#
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/akitect45/cheapai-alluse/main/install.sh | sh
#
# With options:
#   curl -fsSL https://raw.githubusercontent.com/akitect45/cheapai-alluse/main/install.sh | sh -s -- --verify
#   curl -fsSL https://raw.githubusercontent.com/akitect45/cheapai-alluse/main/install.sh | sh -s -- --from-source
#   curl -fsSL https://raw.githubusercontent.com/akitect45/cheapai-alluse/main/install.sh | sh -s -- --uninstall
# ==============================================================================

set -eu

GITHUB_REPO="${ALLUSE_GITHUB_REPO:-akitect45/cheapai-alluse}"
VERSION="${ALLUSE_VERSION:-latest}"
PREFIX="${ALLUSE_PREFIX:-$HOME/.local}"
BIN_DIR="${ALLUSE_BIN_DIR:-}"
INSTALL_DIR="${ALLUSE_INSTALL_DIR:-$HOME/.alluse}"
FROM_SOURCE="${ALLUSE_FROM_SOURCE:-0}"
SKIP_DEPS="${ALLUSE_SKIP_DEPS:-0}"
VERIFY="${ALLUSE_VERIFY:-0}"
UNINSTALL="${ALLUSE_UNINSTALL:-0}"

# Monochrome ANSI styling (disabled if NO_COLOR is set or stdout is not a tty)
if [ -z "${NO_COLOR:-}" ] && [ -t 1 ]; then
    BOLD="\033[1m"
    DIM="\033[2m"
    RESET="\033[0m"
else
    BOLD=""
    DIM=""
    RESET=""
fi

log_info() {
    printf "${BOLD}[AllUse Installer]${RESET} %s\n" "$*"
}

log_step() {
    printf "${BOLD}[AllUse Installer]${RESET} -> %s\n" "$*"
}

log_warn() {
    printf "${BOLD}[AllUse Installer] [WARN]${RESET} %s\n" "$*" >&2
}

log_err() {
    printf "${BOLD}[AllUse Installer] [ERROR]${RESET} %s\n" "$*" >&2
}

print_help() {
    cat <<EOF
AllUse Universal POSIX Installer (macOS & Linux)

Usage:
  install.sh [OPTIONS]

Options:
  -h, --help              Show this help message and exit
  --version <tag>         Install a specific release tag (e.g. v1.0.0; default: latest)
  --prefix <dir>          Installation prefix for symlink (default: ~/.local)
  --bin-dir <dir>         Directory for executable symlink (default: <prefix>/bin)
  --install-dir <dir>     AllUse home directory for binary & source (default: ~/.alluse)
  --from-source           Skip prebuilt binary download and compile via Cargo from source
  --skip-deps             Skip Linux system library checks (WebKitGTK 4.1 / X11 / Wayland)
  --verify                Run 'alluse --version' and 'alluse --doctor' after installation
  --uninstall             Remove AllUse binary and launcher symlink

Environment Variables:
  ALLUSE_VERSION          Same as --version
  ALLUSE_PREFIX           Same as --prefix
  ALLUSE_BIN_DIR          Same as --bin-dir
  ALLUSE_INSTALL_DIR      Same as --install-dir
  ALLUSE_FROM_SOURCE=1    Same as --from-source
  ALLUSE_INSTALL_DEPS=1   Automatically install missing Linux dependencies without prompting
  ALLUSE_SKIP_DEPS=1      Same as --skip-deps
  ALLUSE_VERIFY=1         Same as --verify
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_help
            exit 0
            ;;
        --version)
            if [ $# -lt 2 ]; then
                log_err "--version requires a tag argument"
                exit 1
            fi
            VERSION="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --prefix)
            if [ $# -lt 2 ]; then
                log_err "--prefix requires a directory argument"
                exit 1
            fi
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            shift
            ;;
        --bin-dir)
            if [ $# -lt 2 ]; then
                log_err "--bin-dir requires a directory argument"
                exit 1
            fi
            BIN_DIR="$2"
            shift 2
            ;;
        --bin-dir=*)
            BIN_DIR="${1#*=}"
            shift
            ;;
        --install-dir)
            if [ $# -lt 2 ]; then
                log_err "--install-dir requires a directory argument"
                exit 1
            fi
            INSTALL_DIR="$2"
            shift 2
            ;;
        --install-dir=*)
            INSTALL_DIR="${1#*=}"
            shift
            ;;
        --from-source)
            FROM_SOURCE=1
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=1
            shift
            ;;
        --verify)
            VERIFY=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        *)
            log_err "Unknown option: $1 (run with --help for usage)"
            exit 1
            ;;
    esac
done

if [ -z "$BIN_DIR" ]; then
    BIN_DIR="$PREFIX/bin"
fi

do_uninstall() {
    log_info "Uninstalling AllUse..."
    if [ -L "$BIN_DIR/alluse" ] || [ -f "$BIN_DIR/alluse" ]; then
        rm -f "$BIN_DIR/alluse"
        log_step "Removed launcher symlink: $BIN_DIR/alluse"
    fi
    if [ -d "$INSTALL_DIR/bin" ]; then
        rm -rf "$INSTALL_DIR/bin"
        log_step "Removed binary directory: $INSTALL_DIR/bin"
    fi
    if [ -d "$INSTALL_DIR/src" ]; then
        rm -rf "$INSTALL_DIR/src"
        log_step "Removed source cache: $INSTALL_DIR/src"
    fi
    if [ -d "$INSTALL_DIR" ] && [ -z "$(ls -A "$INSTALL_DIR" 2>/dev/null || true)" ]; then
        rmdir "$INSTALL_DIR" 2>/dev/null || true
    fi
    log_info "AllUse has been uninstalled."
    exit 0
}

if [ "$UNINSTALL" = "1" ]; then
    do_uninstall
fi

detect_platform() {
    OS_RAW="$(uname -s 2>/dev/null || echo Unknown)"
    ARCH_RAW="$(uname -m 2>/dev/null || echo Unknown)"

    case "$OS_RAW" in
        Darwin)
            OS_NAME="darwin"
            # Detect Apple Silicon even if running inside an x86_64 Rosetta 2 shell
            if [ "$ARCH_RAW" = "x86_64" ]; then
                if sysctl -n hw.optional.arm64 2>/dev/null | grep -q "1"; then
                    ARCH_RAW="arm64"
                fi
            fi
            ;;
        Linux)
            OS_NAME="linux"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            log_err "Detected Windows shell ($OS_RAW). Please use the Windows PowerShell installer:"
            log_err "  irm https://raw.githubusercontent.com/$GITHUB_REPO/main/install.ps1 | iex"
            exit 1
            ;;
        *)
            log_err "Unsupported operating system: $OS_RAW"
            exit 1
            ;;
    esac

    case "$ARCH_RAW" in
        arm64|aarch64)
            ARCH_NAME="arm64"
            ;;
        x86_64|amd64)
            ARCH_NAME="x64"
            ;;
        *)
            log_err "Unsupported CPU architecture: $ARCH_RAW"
            exit 1
            ;;
    esac

    PLATFORM_KEY="${OS_NAME}-${ARCH_NAME}"
    case "$PLATFORM_KEY" in
        darwin-arm64)
            PLATFORM_LABEL="macOS Apple Silicon (darwin-arm64)"
            RUST_TARGET="aarch64-apple-darwin"
            ;;
        darwin-x64)
            PLATFORM_LABEL="macOS Intel / Rosetta 2 (darwin-x64)"
            RUST_TARGET="x86_64-apple-darwin"
            ;;
        linux-x64)
            PLATFORM_LABEL="Linux AMD64 (linux-x64)"
            RUST_TARGET="x86_64-unknown-linux-gnu"
            ;;
        linux-arm64)
            PLATFORM_LABEL="Linux ARM64 (linux-arm64)"
            RUST_TARGET="aarch64-unknown-linux-gnu"
            ;;
        *)
            log_err "Unsupported platform combination: $PLATFORM_KEY"
            exit 1
            ;;
    esac
}

have_webkit2gtk_linux() {
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
        return 0
    fi
    if command -v ldconfig >/dev/null 2>&1 && ldconfig -p 2>/dev/null | grep -q "libwebkit2gtk-4.1"; then
        return 0
    fi
    for libdir in /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /lib /lib64; do
        if ls "$libdir"/libwebkit2gtk-4.1.so* >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

ensure_linux_deps() {
    if [ "$OS_NAME" != "linux" ] || [ "$SKIP_DEPS" = "1" ]; then
        return 0
    fi

    # When building from source, pkg-config headers for webkit2gtk-4.1 are required
    NEED_DEV_HEADERS="$FROM_SOURCE"
    if [ "$NEED_DEV_HEADERS" = "1" ]; then
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
            log_step "Linux WebKitGTK 4.1 development headers verified."
            return 0
        fi
    else
        if have_webkit2gtk_linux; then
            log_step "Linux WebKitGTK 4.1 runtime library verified."
            return 0
        fi
    fi

    SUDO_CMD=""
    if [ "$(id -u 2>/dev/null || echo 1)" != "0" ] && command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
    fi

    PKG_INSTALL_CMD=""
    if command -v apt-get >/dev/null 2>&1; then
        PKG_INSTALL_CMD="$SUDO_CMD apt-get update && $SUDO_CMD apt-get install -y build-essential pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libayatana-appindicator3-dev xdotool grim slurp wl-clipboard xclip"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_INSTALL_CMD="$SUDO_CMD dnf install -y gcc gcc-c++ pkgconf-pkg-config webkit2gtk4.1-devel gtk3-devel libxdo-devel libappindicator-gtk3-devel xdotool grim slurp wl-clipboard xclip"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_INSTALL_CMD="$SUDO_CMD pacman -S --needed --noconfirm base-devel pkgconf webkit2gtk-4.1 gtk3 xdotool grim slurp wl-clipboard xclip"
    elif command -v apk >/dev/null 2>&1; then
        PKG_INSTALL_CMD="$SUDO_CMD apk add build-base pkgconf webkit2gtk-4.1-dev gtk+3.0-dev xdotool grim slurp wl-clipboard xclip"
    fi

    log_warn "WebKitGTK 4.1 / CUA display packages were not detected on this Linux system."
    if [ -n "$PKG_INSTALL_CMD" ]; then
        log_info "Recommended command to install system dependencies:"
        printf "  %s\n" "$PKG_INSTALL_CMD"
        if [ "${ALLUSE_INSTALL_DEPS:-0}" = "1" ]; then
            log_step "ALLUSE_INSTALL_DEPS=1 set; installing Linux dependencies..."
            sh -c "$PKG_INSTALL_CMD" || log_warn "Dependency installation returned non-zero; continuing..."
        elif [ -r /dev/tty ]; then
            printf "[AllUse Installer] Install Linux dependencies now? [y/N] " >/dev/tty
            read -r ans </dev/tty || ans="N"
            case "$ans" in
                [yY]|[yY][eE][sS])
                    sh -c "$PKG_INSTALL_CMD" || log_warn "Dependency installation returned non-zero; continuing..."
                    ;;
                *)
                    log_info "Skipping automatic package installation (pass --skip-deps to silence)."
                    ;;
            esac
        else
            log_info "Non-interactive shell detected; set ALLUSE_INSTALL_DEPS=1 to auto-install Linux packages."
        fi
    else
        log_warn "Please install webkit2gtk-4.1, gtk3, libxdo, and xdotool/grim/slurp using your distribution package manager."
    fi
}

print_macos_notes() {
    if [ "$OS_NAME" != "darwin" ]; then
        return 0
    fi
    log_info "macOS Privacy & Security Note (60FPS Computer Use):"
    printf "  ${DIM}Grant 'Accessibility' and 'Screen Recording' permissions to your terminal${RESET}\n"
    printf "  ${DIM}or AllUse binary in: System Settings -> Privacy & Security.${RESET}\n"
}

fetch_url_to_file() {
    SRC_URL="$1"
    DEST_FILE="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 --connect-timeout 15 -o "$DEST_FILE" "$SRC_URL" 2>/dev/null
        return $?
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 15 -O "$DEST_FILE" "$SRC_URL" 2>/dev/null
        return $?
    else
        log_err "Neither 'curl' nor 'wget' is available to download files."
        return 1
    fi
}

validate_native_binary() {
    BIN_FILE="$1"
    if [ ! -f "$BIN_FILE" ]; then
        return 1
    fi
    FILE_SIZE="$(wc -c < "$BIN_FILE" 2>/dev/null | tr -d '[:space:]' || echo 0)"
    # Native binary must be > 1MB (1048576 bytes)
    if [ "${FILE_SIZE:-0}" -lt 1048576 ]; then
        return 1
    fi
    # Validate magic header bytes (ELF: 7f454c46, Mach-O: cffaedfe / cefaedfe / feedfacf / feedface / cafebabe)
    if command -v od >/dev/null 2>&1; then
        MAGIC_HEX="$(od -An -tx1 -N4 "$BIN_FILE" 2>/dev/null | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
        case "$OS_NAME" in
            linux)
                if [ "$MAGIC_HEX" != "7f454c46" ]; then
                    return 1
                fi
                ;;
            darwin)
                case "$MAGIC_HEX" in
                    cffaedfe|cefaedfe|feedfacf|feedface|cafebabe)
                        ;;
                    *)
                        return 1
                        ;;
                esac
                ;;
        esac
    fi
    return 0
}

verify_sha256_if_available() {
    BASE_URL="$1"
    ASSET_NAME="$2"
    FILE_PATH="$3"
    SUMS_FILE="$4"

    if ! fetch_url_to_file "$BASE_URL/SHA256SUMS.txt" "$SUMS_FILE"; then
        return 0
    fi
    EXPECTED_HASH="$(awk -v asset="$ASSET_NAME" '{ f=$2; sub(/^\*/, "", f); if (f == asset || f == "./" asset) { print tolower($1); exit } }' "$SUMS_FILE" 2>/dev/null || true)"
    if [ -z "$EXPECTED_HASH" ]; then
        return 0
    fi
    ACTUAL_HASH=""
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_HASH="$(sha256sum "$FILE_PATH" | awk '{print tolower($1)}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_HASH="$(shasum -a 256 "$FILE_PATH" | awk '{print tolower($1)}')"
    fi
    if [ -n "$ACTUAL_HASH" ]; then
        if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
            log_err "SHA-256 checksum mismatch for $ASSET_NAME!"
            log_err "  Expected: $EXPECTED_HASH"
            log_err "  Actual  : $ACTUAL_HASH"
            return 1
        fi
        log_step "Verified SHA-256 checksum for $ASSET_NAME"
    fi
    return 0
}

try_download_prebuilt() {
    DEST_BIN="$1"
    if [ "$VERSION" = "latest" ]; then
        RELEASE_BASE="https://github.com/$GITHUB_REPO/releases/latest/download"
    else
        RELEASE_BASE="https://github.com/$GITHUB_REPO/releases/download/$VERSION"
    fi

    TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t alluse-install)"
    trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

    CANDIDATE_KEYS="$PLATFORM_KEY"
    if [ "$PLATFORM_KEY" = "darwin-x64" ]; then
        CANDIDATE_KEYS="darwin-x64 darwin-arm64"
    fi

    for KEY in $CANDIDATE_KEYS; do
        RAW_ASSET="alluse-$KEY"
        TAR_ASSET="alluse-$KEY.tar.gz"
        TMP_BIN="$TMP_DIR/$RAW_ASSET"
        TMP_TAR="$TMP_DIR/$TAR_ASSET"
        TMP_SUMS="$TMP_DIR/SHA256SUMS.txt"

        log_step "Checking prebuilt release binary ($RAW_ASSET) from github.com/$GITHUB_REPO..."
        if fetch_url_to_file "$RELEASE_BASE/$RAW_ASSET" "$TMP_BIN"; then
            if verify_sha256_if_available "$RELEASE_BASE" "$RAW_ASSET" "$TMP_BIN" "$TMP_SUMS" && validate_native_binary "$TMP_BIN"; then
                mkdir -p "$(dirname "$DEST_BIN")"
                mv "$TMP_BIN" "$DEST_BIN"
                chmod 755 "$DEST_BIN"
                rm -rf "$TMP_DIR"
                trap - EXIT INT TERM
                log_step "Downloaded verified prebuilt binary ($RAW_ASSET)."
                return 0
            fi
        fi

        if fetch_url_to_file "$RELEASE_BASE/$TAR_ASSET" "$TMP_TAR"; then
            if verify_sha256_if_available "$RELEASE_BASE" "$TAR_ASSET" "$TMP_TAR" "$TMP_SUMS"; then
                mkdir -p "$TMP_DIR/extracted"
                if tar -xzf "$TMP_TAR" -C "$TMP_DIR/extracted" 2>/dev/null; then
                    FOUND_BIN=""
                    if [ -f "$TMP_DIR/extracted/alluse" ]; then
                        FOUND_BIN="$TMP_DIR/extracted/alluse"
                    elif [ -f "$TMP_DIR/extracted/$RAW_ASSET" ]; then
                        FOUND_BIN="$TMP_DIR/extracted/$RAW_ASSET"
                    fi
                    if [ -n "$FOUND_BIN" ] && validate_native_binary "$FOUND_BIN"; then
                        mkdir -p "$(dirname "$DEST_BIN")"
                        mv "$FOUND_BIN" "$DEST_BIN"
                        chmod 755 "$DEST_BIN"
                        rm -rf "$TMP_DIR"
                        trap - EXIT INT TERM
                        log_step "Downloaded and extracted prebuilt archive ($TAR_ASSET)."
                        return 0
                    fi
                fi
            fi
        fi
    done

    rm -rf "$TMP_DIR"
    trap - EXIT INT TERM
    return 1
}

build_from_source() {
    DEST_BIN="$1"
    log_step "Preparing source build for $PLATFORM_LABEL..."

    if [ "$OS_NAME" = "darwin" ]; then
        if ! xcode-select -p >/dev/null 2>&1; then
            log_warn "Xcode Command Line Tools are required to compile on macOS."
            log_warn "Run: xcode-select --install"
        fi
    elif [ "$OS_NAME" = "linux" ]; then
        FROM_SOURCE=1
        ensure_linux_deps
    fi

    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1090
        . "$HOME/.cargo/env"
    fi
    if [ -d "$HOME/.cargo/bin" ]; then
        PATH="$HOME/.cargo/bin:$PATH"
        export PATH
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        log_err "Rust toolchain ('cargo') was not found in PATH."
        log_info "Install Rust in one command via rustup:"
        printf "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n"
        exit 1
    fi

    SRC_WORK_DIR=""
    if [ -f "./Cargo.toml" ] && [ -f "./src/main.rs" ] && grep -q 'name = "alluse"' "./Cargo.toml" 2>/dev/null; then
        SRC_WORK_DIR="$(pwd)"
        log_step "Using local AllUse repository checkout at $SRC_WORK_DIR"
    else
        if ! command -v git >/dev/null 2>&1; then
            log_err "'git' is required to clone https://github.com/$GITHUB_REPO.git for source build."
            exit 1
        fi
        SRC_WORK_DIR="$INSTALL_DIR/src"
        mkdir -p "$INSTALL_DIR"
        if [ -d "$SRC_WORK_DIR/.git" ]; then
            log_step "Updating existing source checkout in $SRC_WORK_DIR..."
            if [ "$VERSION" != "latest" ]; then
                (cd "$SRC_WORK_DIR" && git fetch --depth 1 --tags --force origin "refs/tags/$VERSION:refs/tags/$VERSION" && git checkout -f "$VERSION") >/dev/null 2>&1 || \
                    (cd "$SRC_WORK_DIR" && git fetch --tags --force origin && git checkout -f "$VERSION") >/dev/null 2>&1 || true
            else
                (cd "$SRC_WORK_DIR" && git fetch --depth 1 origin && git reset --hard origin/main) >/dev/null 2>&1 || true
            fi
        else
            rm -rf "$SRC_WORK_DIR"
            log_step "Cloning https://github.com/$GITHUB_REPO.git into $SRC_WORK_DIR..."
            if [ "$VERSION" != "latest" ]; then
                git clone --depth 1 --branch "$VERSION" "https://github.com/$GITHUB_REPO.git" "$SRC_WORK_DIR"
            else
                git clone --depth 1 "https://github.com/$GITHUB_REPO.git" "$SRC_WORK_DIR"
            fi
        fi
    fi

    log_step "Compiling native release binary with 'cargo build --release'..."
    (cd "$SRC_WORK_DIR" && cargo build --release)

    BUILT_BIN="$SRC_WORK_DIR/target/release/alluse"
    if [ ! -f "$BUILT_BIN" ]; then
        log_err "Expected compiled binary at $BUILT_BIN was not found."
        exit 1
    fi

    mkdir -p "$(dirname "$DEST_BIN")"
    cp "$BUILT_BIN" "$DEST_BIN"
    chmod 755 "$DEST_BIN"
    log_step "Installed compiled binary to $DEST_BIN"
}

check_path_hint() {
    case ":$PATH:" in
        *":$BIN_DIR:"*)
            return 0
            ;;
    esac

    log_warn "$BIN_DIR is not currently in your PATH."
    USER_SHELL="$(basename "${SHELL:-sh}")"
    case "$USER_SHELL" in
        zsh)
            log_info "Add it to ~/.zshrc:"
            printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc && source ~/.zshrc\n" "$BIN_DIR"
            ;;
        bash)
            log_info "Add it to ~/.bashrc:"
            printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc && source ~/.bashrc\n" "$BIN_DIR"
            ;;
        fish)
            log_info "Add it to ~/.config/fish/config.fish:"
            printf "  fish_add_path %s\n" "$BIN_DIR"
            ;;
        *)
            log_info "Add the following line to your shell profile (~/.profile):"
            printf "  export PATH=\"%s:\$PATH\"\n" "$BIN_DIR"
            ;;
    esac
}

main() {
    detect_platform
    log_info "Target Platform : $PLATFORM_LABEL ($RUST_TARGET)"
    log_info "Install Dir     : $INSTALL_DIR"
    log_info "Launcher Symlink: $BIN_DIR/alluse"

    ensure_linux_deps

    TARGET_BIN="$INSTALL_DIR/bin/alluse"
    mkdir -p "$INSTALL_DIR/bin" "$BIN_DIR"

    if [ "$FROM_SOURCE" = "1" ]; then
        build_from_source "$TARGET_BIN"
    else
        if ! try_download_prebuilt "$TARGET_BIN"; then
            log_warn "Prebuilt binary not available for $PLATFORM_KEY ($VERSION); falling back to Cargo source build..."
            build_from_source "$TARGET_BIN"
        fi
    fi

    ln -sf "$TARGET_BIN" "$BIN_DIR/alluse"
    log_step "Linked $BIN_DIR/alluse -> $TARGET_BIN"

    print_macos_notes
    check_path_hint

    if [ "$VERIFY" = "1" ]; then
        log_step "Running verification (--version & --doctor)..."
        "$TARGET_BIN" --version
        "$TARGET_BIN" --doctor
    fi

    log_info "AllUse installation complete! Run 'alluse' (or '$BIN_DIR/alluse') to launch."
}

main
