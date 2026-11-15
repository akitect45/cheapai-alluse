#!/usr/bin/env node
/**
 * AllUse Universal Cross-Platform Launcher (`bin/alluse.js`)
 *
 * Supports all 5 official OS / Architecture targets (plus Intel Mac fallback):
 *   1. macOS Apple Silicon : darwin-arm64  (aarch64-apple-darwin)
 *   2. Linux AMD64         : linux-x64     (x86_64-unknown-linux-gnu)
 *   3. Linux ARM64         : linux-arm64   (aarch64-unknown-linux-gnu)
 *   4. Windows ARM64       : win32-arm64   (aarch64-pc-windows-gnullvm / msvc)
 *   5. Windows AMD64       : win32-x64     (x86_64-pc-windows-gnu / msvc)
 *
 * Usage:
 *   npm start / npx alluse            # Launch native desktop GUI workbench
 *   npx alluse --web                  # Launch HTTP/SSE server + open system browser
 *   npx alluse --doctor               # Run platform & dependency doctor diagnostics
 *   npx alluse --launcher-doctor      # Print Node launcher environment diagnostics
 *   npx alluse --verify               # Run self-verification suite
 *   npx alluse --heal                 # Run self-healing diagnostics
 *   npx alluse --build                # Force cargo build --release for current host
 */

const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const GITHUB_REPO = process.env.ALLUSE_GITHUB_REPO || "akitect45/cheapai-alluse";

const SUPPORTED_TARGETS = {
  "darwin-arm64": {
    label: "macOS Apple Silicon (ARM64)",
    rustTargets: ["aarch64-apple-darwin"],
    binName: "alluse",
    releaseAsset: "alluse-darwin-arm64",
  },
  "darwin-x64": {
    label: "macOS Intel / Rosetta 2 (x86_64)",
    rustTargets: ["x86_64-apple-darwin", "aarch64-apple-darwin"],
    binName: "alluse",
    releaseAsset: "alluse-darwin-x64",
    fallbackAsset: "alluse-darwin-arm64",
  },
  "linux-x64": {
    label: "Linux AMD64 (x86_64)",
    rustTargets: ["x86_64-unknown-linux-gnu"],
    binName: "alluse",
    releaseAsset: "alluse-linux-x64",
  },
  "linux-arm64": {
    label: "Linux ARM64 (aarch64)",
    rustTargets: ["aarch64-unknown-linux-gnu"],
    binName: "alluse",
    releaseAsset: "alluse-linux-arm64",
  },
  "win32-arm64": {
    label: "Windows 11 ARM64 (aarch64)",
    rustTargets: ["aarch64-pc-windows-gnullvm", "aarch64-pc-windows-msvc"],
    binName: "alluse.exe",
    releaseAsset: "alluse-win32-arm64.exe",
    wv2Arch: "arm64",
    mingwTriple: "aarch64-w64-mingw32",
  },
  "win32-x64": {
    label: "Windows AMD64 (x86_64)",
    rustTargets: ["x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu"],
    binName: "alluse.exe",
    releaseAsset: "alluse-win32-x64.exe",
    wv2Arch: "x64",
    mingwTriple: "x86_64-w64-mingw32",
  },
};

function resolveHostTarget() {
  let arch = process.arch;
  if (process.platform === "win32") {
    const wow64 = (process.env.PROCESSOR_ARCHITEW6432 || "").toLowerCase();
    const procArch = (process.env.PROCESSOR_ARCHITECTURE || "").toLowerCase();
    if (wow64.includes("arm64") || procArch.includes("arm64")) {
      arch = "arm64";
    }
  } else if (process.platform === "darwin" && arch === "x64") {
    try {
      const res = spawnSync("sysctl", ["-n", "hw.optional.arm64"], {
        stdio: ["ignore", "pipe", "ignore"],
        encoding: "utf8",
      });
      if (res.status === 0 && String(res.stdout || "").trim() === "1") {
        arch = "arm64";
      }
    } catch (_) {}
  }
  const key = `${process.platform}-${arch}`;
  if (SUPPORTED_TARGETS[key]) {
    return { key, ...SUPPORTED_TARGETS[key] };
  }
  const isWin = process.platform === "win32";
  return {
    key,
    label: `${process.platform} (${arch})`,
    rustTargets: [],
    binName: isWin ? "alluse.exe" : "alluse",
    releaseAsset: `alluse-${key}${isWin ? ".exe" : ""}`,
    wv2Arch: arch === "arm64" ? "arm64" : "x64",
    mingwTriple:
      arch === "arm64" ? "aarch64-w64-mingw32" : "x86_64-w64-mingw32",
  };
}

function candidateHomeDirs() {
  const cargoExeName = process.platform === "win32" ? "cargo.exe" : "cargo";
  const dirs = [
    os.homedir(),
    process.env.USERPROFILE,
    process.env.HOME,
    process.platform === "win32" && process.env.USERNAME
      ? path.join("C:\\Users", process.env.USERNAME)
      : null,
  ].filter(Boolean);
  if (process.platform === "win32" && fs.existsSync("C:\\Users")) {
    try {
      for (const entry of fs.readdirSync("C:\\Users")) {
        const uDir = path.join("C:\\Users", entry);
        if (fs.existsSync(path.join(uDir, ".cargo", "bin", cargoExeName))) {
          dirs.push(uDir);
        }
      }
    } catch (_) {}
  }
  return [...new Set(dirs)];
}

function buildCargoEnv() {
  const cargoExeName = process.platform === "win32" ? "cargo.exe" : "cargo";
  const env = { ...process.env };
  const pathSep = process.platform === "win32" ? ";" : ":";
  const pathKey =
    Object.keys(env).find((k) => k.toLowerCase() === "path") || "PATH";
  for (const home of candidateHomeDirs()) {
    const cargoDir = path.join(home, ".cargo");
    const cargoBin = path.join(cargoDir, "bin");
    const cargoExe = path.join(cargoBin, cargoExeName);
    const rustupDir = path.join(home, ".rustup");
    const llvmMingwBin = path.join(home, ".llvm-mingw", "bin");
    if (fs.existsSync(cargoExe) && !env.CARGO_HOME) {
      env.CARGO_HOME = cargoDir;
      process.env.CARGO_HOME = cargoDir;
    }
    if (
      fs.existsSync(path.join(rustupDir, "settings.toml")) &&
      !env.RUSTUP_HOME
    ) {
      env.RUSTUP_HOME = rustupDir;
      process.env.RUSTUP_HOME = rustupDir;
    }
    for (const extraDir of [
      llvmMingwBin,
      cargoBin,
      ...(process.platform !== "win32"
        ? [
            path.join(home, ".local", "bin"),
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/usr/local/bin",
            "/home/linuxbrew/.linuxbrew/bin",
          ]
        : []),
    ]) {
      if (fs.existsSync(extraDir) && !(env[pathKey] || "").includes(extraDir)) {
        env[pathKey] = `${extraDir}${pathSep}${env[pathKey] || ""}`;
      }
    }
  }
  process.env[pathKey] = env[pathKey];
  return env;
}

function resolveCargoExecutable() {
  const cargoExeName = process.platform === "win32" ? "cargo.exe" : "cargo";
  for (const home of candidateHomeDirs()) {
    const homeCargo = path.join(home, ".cargo", "bin", cargoExeName);
    if (fs.existsSync(homeCargo)) {
      return homeCargo;
    }
    if (process.platform !== "win32") {
      for (const extraDir of [
        path.join(home, ".local", "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/home/linuxbrew/.linuxbrew/bin",
      ]) {
        const cand = path.join(extraDir, cargoExeName);
        if (fs.existsSync(cand)) {
          return cand;
        }
      }
    }
  }
  return cargoExeName;
}

function hasValidMzHeader(filePath, minBytes = 40960) {
  try {
    if (!fs.existsSync(filePath)) return false;
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size < minBytes) return false;
    const fd = fs.openSync(filePath, "r");
    try {
      const buf = Buffer.alloc(2);
      const bytesRead = fs.readSync(fd, buf, 0, 2, 0);
      return bytesRead === 2 && buf[0] === 0x4d && buf[1] === 0x5a;
    } finally {
      fs.closeSync(fd);
    }
  } catch (_) {
    return false;
  }
}

function hasValidNativeBinaryHeader(filePath, minBytes = 65536) {
  try {
    if (!fs.existsSync(filePath)) return false;
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size < minBytes) return false;
    const fd = fs.openSync(filePath, "r");
    try {
      const buf = Buffer.alloc(4);
      const bytesRead = fs.readSync(fd, buf, 0, 4, 0);
      if (bytesRead < 2) return false;
      if (process.platform === "win32") {
        return buf[0] === 0x4d && buf[1] === 0x5a;
      }
      if (bytesRead < 4) return false;
      if (process.platform === "linux") {
        return (
          buf[0] === 0x7f &&
          buf[1] === 0x45 &&
          buf[2] === 0x4c &&
          buf[3] === 0x46
        );
      }
      if (process.platform === "darwin") {
        const magicBE = buf.readUInt32BE(0);
        return (
          magicBE === 0xcffaedfe ||
          magicBE === 0xfeedfacf ||
          magicBE === 0xcafebabe ||
          magicBE === 0xbebafeca ||
          magicBE === 0xcefaedfe ||
          magicBE === 0xfeedface
        );
      }
      return !(buf[0] === 0x23 && buf[1] === 0x21);
    } finally {
      fs.closeSync(fd);
    }
  } catch (_) {
    return false;
  }
}

function findWebView2DllInCargoTarget(arch) {
  const buildDirs = [
    path.join(PROJECT_ROOT, "target", "release", "build"),
    path.join(PROJECT_ROOT, "target", "debug", "build"),
  ];
  for (const bDir of buildDirs) {
    if (!fs.existsSync(bDir)) continue;
    try {
      const entries = fs.readdirSync(bDir);
      for (const entry of entries) {
        if (!entry.startsWith("webview2-com-sys-")) continue;
        const candidate = path.join(
          bDir,
          entry,
          "out",
          arch,
          "WebView2Loader.dll"
        );
        if (hasValidMzHeader(candidate, 40960)) {
          return candidate;
        }
      }
    } catch (_) {}
  }
  return null;
}

function findLocalWebView2Dll(targetInfo) {
  const arch = targetInfo.wv2Arch || (process.arch === "arm64" ? "arm64" : "x64");
  const dllBakDir = path.join(PROJECT_ROOT, "data", "backups", "dlls");
  const candidates = [
    path.join(PROJECT_ROOT, "windows-webview2-src", arch, "WebView2Loader.dll"),
    path.join(dllBakDir, "WebView2Loader.dll"),
    path.join(PROJECT_ROOT, "target", "release", "WebView2Loader.dll"),
    findWebView2DllInCargoTarget(arch),
    path.join(PROJECT_ROOT, "WebView2Loader.dll"),
  ].filter(Boolean);

  return candidates.find((p) => hasValidMzHeader(p, 40960)) || null;
}

async function ensureWindowsRuntimeDlls(
  targetInfo,
  dirPath,
  allowNetworkDownload = true
) {
  if (process.platform !== "win32" || !dirPath) return;
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (_) {}

  const arch = targetInfo.wv2Arch || (process.arch === "arm64" ? "arm64" : "x64");
  const dllBakDir = path.join(PROJECT_ROOT, "data", "backups", "dlls");
  const wv2Dest = path.join(dirPath, "WebView2Loader.dll");

  if (!hasValidMzHeader(wv2Dest, 40960)) {
    const localFound = findLocalWebView2Dll(targetInfo);
    if (localFound && path.resolve(localFound) !== path.resolve(wv2Dest)) {
      try {
        fs.copyFileSync(localFound, wv2Dest);
      } catch (_) {}
    } else if (allowNetworkDownload) {
      const dllAsset = `WebView2Loader-${arch}.dll`;
      const dllUrl = `https://github.com/${GITHUB_REPO}/releases/latest/download/${dllAsset}`;
      console.log(
        `[AllUse] Downloading ${dllAsset} from github.com/${GITHUB_REPO}...`
      );
      const ok = await downloadFileWithRedirects(dllUrl, wv2Dest, 5, 40960);
      if (ok && !hasValidMzHeader(wv2Dest, 40960)) {
        try {
          fs.unlinkSync(wv2Dest);
        } catch (_) {}
      }
    }
  }

  const unwindDest = path.join(dirPath, "libunwind.dll");
  if (!fs.existsSync(unwindDest)) {
    const home = os.homedir();
    const candidates = [
      path.join(dllBakDir, "libunwind.dll"),
      path.join(
        home,
        ".llvm-mingw",
        targetInfo.mingwTriple || "aarch64-w64-mingw32",
        "bin",
        "libunwind.dll"
      ),
      path.join(PROJECT_ROOT, "libunwind.dll"),
    ];
    const found = candidates.find((p) => fs.existsSync(p));
    if (found) {
      try {
        fs.copyFileSync(found, unwindDest);
      } catch (_) {}
    }
  }
}

function findExistingBinary(targetInfo) {
  const bin = targetInfo.binName;
  const candidates = [
    path.join(PROJECT_ROOT, "target", "release", bin),
    ...targetInfo.rustTargets.map((t) =>
      path.join(PROJECT_ROOT, "target", t, "release", bin)
    ),
    path.join(PROJECT_ROOT, "dist", targetInfo.key, bin),
    path.join(
      PROJECT_ROOT,
      "data",
      "backups",
      process.platform === "win32" ? "alluse_golden.exe" : "alluse_golden"
    ),
    path.join(PROJECT_ROOT, "target", "debug", bin),
  ];
  return candidates.find((p) => hasValidNativeBinaryHeader(p, 65536));
}

function downloadFileWithRedirects(
  url,
  destPath,
  redirectsLeft = 5,
  minSizeBytes = 65536
) {
  return new Promise((resolve) => {
    if (redirectsLeft <= 0) return resolve(false);
    const tmpPath = `${destPath}.part`;
    const cleanupTmp = () => {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch (_) {}
    };
    const req = https.get(
      url,
      { headers: { "User-Agent": "alluse-launcher/1.0" }, timeout: 15000 },
      (res) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          res.resume();
          let nextUrl;
          try {
            nextUrl = new URL(res.headers.location, url).toString();
          } catch (_) {
            return resolve(false);
          }
          return resolve(
            downloadFileWithRedirects(
              nextUrl,
              destPath,
              redirectsLeft - 1,
              minSizeBytes
            )
          );
        }
        if (res.statusCode !== 200) {
          res.resume();
          return resolve(false);
        }
        const expectedLen = res.headers["content-length"]
          ? parseInt(res.headers["content-length"], 10)
          : null;
        const fileStream = fs.createWriteStream(tmpPath);
        res.on("error", () => {
          fileStream.destroy();
          cleanupTmp();
          resolve(false);
        });
        res.pipe(fileStream);
        fileStream.on("finish", () => {
          fileStream.close(() => {
            try {
              if (!res.complete) {
                cleanupTmp();
                return resolve(false);
              }
              const sz = fs.statSync(tmpPath).size;
              if (
                sz < minSizeBytes ||
                (Number.isFinite(expectedLen) &&
                  expectedLen > 0 &&
                  sz !== expectedLen)
              ) {
                cleanupTmp();
                return resolve(false);
              }
              fs.renameSync(tmpPath, destPath);
              if (process.platform !== "win32") {
                fs.chmodSync(destPath, 0o755);
              }
              resolve(true);
            } catch (_) {
              cleanupTmp();
              resolve(false);
            }
          });
        });
        fileStream.on("error", () => {
          cleanupTmp();
          resolve(false);
        });
      }
    );
    req.on("error", () => {
      cleanupTmp();
      resolve(false);
    });
    req.on("timeout", () => {
      req.destroy();
      cleanupTmp();
      resolve(false);
    });
  });
}

async function tryDownloadPrebuiltReleaseBinary(targetInfo) {
  if (!targetInfo.releaseAsset) return null;
  const distDir = path.join(PROJECT_ROOT, "dist", targetInfo.key);
  const destBin = path.join(distDir, targetInfo.binName);
  const assetsToTry = [targetInfo.releaseAsset];
  if (targetInfo.fallbackAsset) {
    assetsToTry.push(targetInfo.fallbackAsset);
  }

  try {
    fs.mkdirSync(distDir, { recursive: true });
    for (const assetName of assetsToTry) {
      const url = `https://github.com/${GITHUB_REPO}/releases/latest/download/${assetName}`;
      console.log(
        `[AllUse] Checking prebuilt release binary from github.com/${GITHUB_REPO} (${assetName})...`
      );
      const ok = await downloadFileWithRedirects(url, destBin, 5, 65536);
      if (ok && fs.existsSync(destBin)) {
        if (!hasValidNativeBinaryHeader(destBin, 1048576)) {
          try {
            fs.unlinkSync(destBin);
          } catch (_) {}
          continue;
        }
        console.log(
          `[AllUse] Downloaded prebuilt binary to ${path.relative(PROJECT_ROOT, destBin)}`
        );
        if (process.platform === "win32") {
          await ensureWindowsRuntimeDlls(targetInfo, distDir, true);
          const releaseDir = path.join(PROJECT_ROOT, "target", "release");
          if (fs.existsSync(releaseDir)) {
            await ensureWindowsRuntimeDlls(targetInfo, releaseDir, false);
          }
        }
        return destBin;
      }
    }
  } catch (_) {}
  return null;
}

async function buildNativeBinary(targetInfo) {
  console.log(
    `[AllUse] Building native binary for ${targetInfo.label} (${targetInfo.key})...`
  );
  const env = buildCargoEnv();
  const cargoCmd = resolveCargoExecutable();
  const res = spawnSync(cargoCmd, ["build", "--release"], {
    cwd: PROJECT_ROOT,
    env,
    stdio: "inherit",
  });
  if (res.status !== 0) {
    console.error(
      `[AllUse] cargo build --release failed with status ${res.status}.`
    );
    process.exit(res.status || 1);
  }
  const releaseDir = path.join(PROJECT_ROOT, "target", "release");
  await ensureWindowsRuntimeDlls(targetInfo, releaseDir, true);
}

function cleanupLegacyRootWindowsArtifacts() {
  if (process.platform !== "win32") return;
  for (const name of [
    "alluse.exe",
    "alluse.exe.old",
    "WebView2Loader.dll",
    "libunwind.dll",
  ]) {
    const p = path.join(PROJECT_ROOT, name);
    if (fs.existsSync(p)) {
      try {
        fs.unlinkSync(p);
      } catch (_) {}
    }
  }
}

function collectLauncherDiagnostics(targetInfo, resolvedBinPath) {
  const env = buildCargoEnv();
  const cargoCmd = resolveCargoExecutable();
  let cargoAvailable = false;
  try {
    const res = spawnSync(cargoCmd, ["--version"], {
      env,
      stdio: "pipe",
    });
    cargoAvailable = res.status === 0;
  } catch (_) {
    cargoAvailable = false;
  }

  const binaryPath = resolvedBinPath || findExistingBinary(targetInfo) || null;
  let webview2DllPresent = true;
  if (process.platform === "win32") {
    const checkDir = binaryPath
      ? path.dirname(binaryPath)
      : path.join(PROJECT_ROOT, "target", "release");
    const dllNextToBin = path.join(checkDir, "WebView2Loader.dll");
    webview2DllPresent =
      hasValidMzHeader(dllNextToBin, 40960) ||
      Boolean(findLocalWebView2Dll(targetInfo));
  }

  return {
    platformKey: targetInfo.key,
    rustTarget: targetInfo.rustTargets[0] || "unknown",
    binaryPath,
    webview2DllPresent,
    cargoAvailable,
  };
}

function printLauncherDoctorReport(diag) {
  console.log("[AllUse Launcher Doctor] Node Wrapper Environment Diagnostics:");
  console.log(`  platformKey        : ${diag.platformKey}`);
  console.log(`  rustTarget         : ${diag.rustTarget}`);
  console.log(`  binaryPath         : ${diag.binaryPath || "(not built yet)"}`);
  console.log(`  webview2DllPresent : ${diag.webview2DllPresent}`);
  console.log(`  cargoAvailable     : ${diag.cargoAvailable}`);
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const targetInfo = resolveHostTarget();
  cleanupLegacyRootWindowsArtifacts();

  const wantsLauncherDoctor = rawArgs.includes("--launcher-doctor");
  const wantsDoctor = rawArgs.includes("--doctor");

  if (wantsLauncherDoctor) {
    const diag = collectLauncherDiagnostics(targetInfo, null);
    printLauncherDoctorReport(diag);
    if (!wantsDoctor) {
      return;
    }
  }

  if (rawArgs.includes("--build")) {
    await buildNativeBinary(targetInfo);
    const filtered = rawArgs.filter((a) => a !== "--build");
    if (filtered.length === 0) {
      return;
    }
  }

  let binPath = findExistingBinary(targetInfo);
  if (wantsDoctor && !binPath && !wantsLauncherDoctor) {
    const diag = collectLauncherDiagnostics(targetInfo, null);
    printLauncherDoctorReport(diag);
  }

  if (!binPath) {
    binPath = await tryDownloadPrebuiltReleaseBinary(targetInfo);
  }
  if (!binPath) {
    await buildNativeBinary(targetInfo);
    binPath = findExistingBinary(targetInfo);
  }

  if (!binPath) {
    console.error(
      `[AllUse] Could not locate or build native binary for ${targetInfo.label}.`
    );
    process.exit(1);
  }

  await ensureWindowsRuntimeDlls(targetInfo, path.dirname(binPath), true);

  const forwardArgs = rawArgs.filter(
    (a) => a !== "--build" && a !== "--wait" && a !== "--launcher-doctor"
  );
  const child = spawn(binPath, forwardArgs, {
    cwd: PROJECT_ROOT,
    env: buildCargoEnv(),
    stdio: "inherit",
  });

  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      try {
        if (child && !child.killed) {
          child.kill(sig);
        }
      } catch (_) {}
    });
  }

  child.on("error", (err) => {
    console.error(`[AllUse] Failed to spawn ${binPath}: ${err.message}`);
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.exit(1);
    }
    process.exit(code == null ? 0 : code);
  });
}

main();
