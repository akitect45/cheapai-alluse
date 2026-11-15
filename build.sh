#!/usr/bin/env sh
# Build & package CheapAI AllUse + native custom installer (`alluse` + `alluse-setup`)
# for macOS (arm64 / x64) and Linux (x64 / arm64).
# Uses `--target <triple>` so `target/release/alluse` is never overwritten.
#
# Usage:
#   ./build.sh
#   ./build.sh --target macos-arm64
#   ./build.sh --target macos-x64
#   ./build.sh --target linux-x64
#   ./build.sh --target linux-arm64
#   ./build.sh --target all
#   ./build.sh --cargo-only

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT_DIR"

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  . "$HOME/.cargo/env"
fi
if [ -d "$HOME/.cargo/bin" ]; then
  PATH="$HOME/.cargo/bin:$PATH"
  export PATH
fi

TARGET_ARG="auto"
CARGO_ONLY=0
VERSION_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      shift
      TARGET_ARG="${1:-auto}"
      ;;
    --target=*)
      TARGET_ARG="${1#*=}"
      ;;
    --cargo-only)
      CARGO_ONLY=1
      ;;
    --version)
      shift
      VERSION_OVERRIDE="${1:-}"
      ;;
    --version=*)
      VERSION_OVERRIDE="${1#*=}"
      ;;
    -h|--help)
      echo "Usage: ./build.sh [--target auto|macos-arm64|macos-x64|linux-x64|linux-arm64|all] [--cargo-only] [--version <semver>]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
  shift
done

resolve_version() {
  if [ -n "$VERSION_OVERRIDE" ]; then
    printf '%s' "${VERSION_OVERRIDE#v}"
    return
  fi
  if [ -f "$ROOT_DIR/Cargo.toml" ]; then
    V="$(awk -F'"' '/^[[:space:]]*version[[:space:]]*=/{print $2; exit}' "$ROOT_DIR/Cargo.toml")"
    if [ -n "$V" ]; then
      printf '%s' "$V"
      return
    fi
  fi
  printf '1.0.0'
}

UNAME_S="$(uname -s 2>/dev/null || echo Unknown)"
UNAME_M="$(uname -m 2>/dev/null || echo Unknown)"

resolve_host_os() {
  case "$UNAME_S" in
    Darwin) echo "macos" ;;
    Linux) echo "linux" ;;
    *)
      echo "Error: Unsupported OS '$UNAME_S'. Use build.ps1 on Windows." >&2
      exit 1
      ;;
  esac
}

resolve_host_arch() {
  ARCH_RAW="$UNAME_M"
  if [ "$UNAME_S" = "Darwin" ] && [ "$ARCH_RAW" = "x86_64" ]; then
    if sysctl -n hw.optional.arm64 2>/dev/null | grep -q "1"; then
      ARCH_RAW="arm64"
    fi
  fi
  case "$ARCH_RAW" in
    arm64|aarch64) echo "arm64" ;;
    x86_64|amd64) echo "x64" ;;
    *)
      echo "Error: Unsupported host arch '$ARCH_RAW'." >&2
      exit 1
      ;;
  esac
}

HOST_OS="$(resolve_host_os)"
HOST_ARCH="$(resolve_host_arch)"
VERSION="$(resolve_version)"

expand_targets() {
  case "$1" in
    auto)
      echo "${HOST_OS}-${HOST_ARCH}"
      ;;
    all)
      if [ "$HOST_OS" = "macos" ]; then
        echo "macos-arm64 macos-x64"
      else
        if [ "$HOST_ARCH" = "x64" ] && command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
          echo "linux-x64 linux-arm64"
        elif [ "$HOST_ARCH" = "arm64" ] && command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
          echo "linux-arm64 linux-x64"
        else
          echo "linux-${HOST_ARCH}"
        fi
      fi
      ;;
    macos-arm64|darwin-arm64|aarch64-apple-darwin)
      echo "macos-arm64"
      ;;
    macos-x64|darwin-x64|x86_64-apple-darwin)
      echo "macos-x64"
      ;;
    linux-x64|x86_64-unknown-linux-gnu)
      echo "linux-x64"
      ;;
    linux-arm64|aarch64-unknown-linux-gnu)
      echo "linux-arm64"
      ;;
    *)
      echo "Error: Unsupported target '$1'." >&2
      exit 1
      ;;
  esac
}

TARGET_LIST="$(expand_targets "$TARGET_ARG")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Install Rust via https://rustup.rs/" >&2
  exit 1
fi

ICONS_DIR="$ROOT_DIR/target/installer-icons"
PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PY_BIN="python"
fi

if [ "$CARGO_ONLY" -eq 0 ]; then
  if ! command -v node >/dev/null 2>&1; then
    echo "Error: Node.js >= 18 is required for ALLUSE_PKG_V1 packaging (or pass --cargo-only)." >&2
    exit 1
  fi
  if [ -z "$PY_BIN" ]; then
    echo "Error: python3/python is required to generate installer icons (or pass --cargo-only)." >&2
    exit 1
  fi
  echo "[AllUse Build] Generating cross-platform icons in $ICONS_DIR..."
  "$PY_BIN" "$ROOT_DIR/scripts/generate-icons.py" --out-dir "$ICONS_DIR" >/dev/null
fi

DIST_MACOS="$ROOT_DIR/dist/macos"
DIST_LINUX="$ROOT_DIR/dist/linux"
BUILT_MACOS=0
BUILT_LINUX=0

for SPEC in $TARGET_LIST; do
  case "$SPEC" in
    macos-arm64)
      OS_KIND="macos"
      ARCH_KEY="arm64"
      TRIPLE="aarch64-apple-darwin"
      ;;
    macos-x64)
      OS_KIND="macos"
      ARCH_KEY="x64"
      TRIPLE="x86_64-apple-darwin"
      ;;
    linux-x64)
      OS_KIND="linux"
      ARCH_KEY="x64"
      TRIPLE="x86_64-unknown-linux-gnu"
      ;;
    linux-arm64)
      OS_KIND="linux"
      ARCH_KEY="arm64"
      TRIPLE="aarch64-unknown-linux-gnu"
      ;;
  esac

  echo ""
  echo "=== Building $SPEC ($TRIPLE) ==="
  if command -v rustup >/dev/null 2>&1; then
    rustup target add "$TRIPLE"
  fi

  if [ "$OS_KIND" = "linux" ] && [ "$ARCH_KEY" != "$HOST_ARCH" ]; then
    if [ "$ARCH_KEY" = "arm64" ] && command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
      export CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
    elif [ "$ARCH_KEY" = "x64" ] && command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="x86_64-linux-gnu-gcc"
      export CC_x86_64_unknown_linux_gnu="x86_64-linux-gnu-gcc"
    fi
  fi

  cargo build --release --target "$TRIPLE" --bin alluse --bin alluse-setup

  BIN_APP="$ROOT_DIR/target/$TRIPLE/release/alluse"
  BIN_SETUP="$ROOT_DIR/target/$TRIPLE/release/alluse-setup"
  if [ ! -f "$BIN_APP" ] || [ ! -f "$BIN_SETUP" ]; then
    echo "Error: expected binaries missing under target/$TRIPLE/release/" >&2
    exit 1
  fi

  if [ "$CARGO_ONLY" -eq 1 ]; then
    echo "[AllUse Build] --cargo-only: built $BIN_APP and $BIN_SETUP"
    continue
  fi

  if [ "$OS_KIND" = "macos" ]; then
    mkdir -p "$DIST_MACOS"
    STAGE_DIR="$DIST_MACOS/stage-${ARCH_KEY}"
    APP_BUNDLE="$STAGE_DIR/AllUse Installer.app"
    rm -rf "$STAGE_DIR"
    mkdir -p "$STAGE_DIR"

    node "$ROOT_DIR/scripts/package-installer.mjs" \
      --os macos \
      --arch "$ARCH_KEY" \
      --version "$VERSION" \
      --macos-app \
      --stub "$BIN_SETUP" \
      --icon "$ICONS_DIR/AppIcon.icns" \
      --input "${BIN_APP}:alluse" \
      --input "$ICONS_DIR/AppIcon.icns:AppIcon.icns" \
      --input "$ROOT_DIR/LICENSE:LICENSE" \
      --out "$APP_BUNDLE"

    node "$ROOT_DIR/scripts/package-installer.mjs" --verify "$APP_BUNDLE/Contents/Resources/payload.pak" >/dev/null

    cp "$BIN_APP" "$DIST_MACOS/alluse-darwin-${ARCH_KEY}"
    chmod 755 "$DIST_MACOS/alluse-darwin-${ARCH_KEY}"

    TAR_OUT="$DIST_MACOS/AllUse-Setup-${VERSION}-darwin-${ARCH_KEY}.app.tar.gz"
    tar -C "$STAGE_DIR" -czf "$TAR_OUT" "AllUse Installer.app"

    if command -v hdiutil >/dev/null 2>&1; then
      DMG_OUT="$DIST_MACOS/AllUse-Setup-${VERSION}-darwin-${ARCH_KEY}.dmg"
      rm -f "$DMG_OUT"
      ln -s /Applications "$STAGE_DIR/Applications" 2>/dev/null || true
      hdiutil create -volname "CheapAI AllUse Setup" -srcfolder "$STAGE_DIR" -ov -format UDZO "$DMG_OUT" >/dev/null
    fi
    rm -rf "$STAGE_DIR"
    BUILT_MACOS=1
  else
    mkdir -p "$DIST_LINUX"
    RUN_OUT="$DIST_LINUX/AllUse-Setup-${VERSION}-linux-${ARCH_KEY}.run"
    node "$ROOT_DIR/scripts/package-installer.mjs" \
      --os linux \
      --arch "$ARCH_KEY" \
      --version "$VERSION" \
      --stub "$BIN_SETUP" \
      --input "${BIN_APP}:alluse" \
      --input "$ICONS_DIR/alluse.png:alluse.png" \
      --input "$ROOT_DIR/LICENSE:LICENSE" \
      --out "$RUN_OUT"
    chmod 755 "$RUN_OUT"

    if [ "$ARCH_KEY" = "$HOST_ARCH" ]; then
      "$RUN_OUT" --verify-payload
    else
      node "$ROOT_DIR/scripts/package-installer.mjs" --verify "$RUN_OUT" >/dev/null
    fi

    cp "$BIN_APP" "$DIST_LINUX/alluse-linux-${ARCH_KEY}"
    chmod 755 "$DIST_LINUX/alluse-linux-${ARCH_KEY}"

    TAR_STAGE="$DIST_LINUX/stage-${ARCH_KEY}"
    rm -rf "$TAR_STAGE"
    mkdir -p "$TAR_STAGE"
    cp "$BIN_APP" "$TAR_STAGE/alluse"
    chmod 755 "$TAR_STAGE/alluse"
    cp "$ICONS_DIR/alluse.png" "$TAR_STAGE/alluse.png"
    cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$ROOT_DIR/install.sh" "$TAR_STAGE/"
    tar -C "$TAR_STAGE" -czf "$DIST_LINUX/alluse-${VERSION}-linux-${ARCH_KEY}.tar.gz" .
    rm -rf "$TAR_STAGE"
    BUILT_LINUX=1
  fi
done

if [ "$CARGO_ONLY" -eq 0 ]; then
  if [ "$BUILT_MACOS" -eq 1 ]; then
    node "$ROOT_DIR/scripts/generate-release-manifest.mjs" --version "$VERSION" --dir "$DIST_MACOS"
    echo "[AllUse Build] macOS distribution ready in $DIST_MACOS"
  fi
  if [ "$BUILT_LINUX" -eq 1 ]; then
    node "$ROOT_DIR/scripts/generate-release-manifest.mjs" --version "$VERSION" --dir "$DIST_LINUX"
    echo "[AllUse Build] Linux distribution ready in $DIST_LINUX"
  fi
fi
