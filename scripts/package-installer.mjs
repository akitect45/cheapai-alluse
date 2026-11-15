#!/usr/bin/env node
/**
 * CheapAI AllUse Cross-Platform Installer Payload Packer (`ALLUSE_PKG_V1`)
 *
 * Binary layout (must stay byte-exact with `src/bin/alluse_setup.rs`):
 *   Uncompressed archive:
 *     [manifest_len: u32 LE (4B)][manifest_json_utf8][raw_concatenated_file_bytes]
 *   `manifest_json`:
 *     { "format": "alluse-pkg-v1", "version": "...", "os": "windows"|"macos"|"linux",
 *       "arch": "arm64"|"x64", "files": [{ "name", "offset", "size", "mode", "sha256" }] }
 *   Gzip + 56-byte footer:
 *     [gzip_bytes][gz_len: u64 LE (8B)][gz_sha256_raw_bytes: 32B]["ALLUSE_PKG_V1\0\0\0" (16B)]
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

export const PACKAGE_FORMAT = 'alluse-pkg-v1';
export const PACKAGE_MAGIC = Buffer.from('ALLUSE_PKG_V1\0\0\0', 'ascii');
export const FOOTER_SIZE = 56; // 8 (u64 LE gz_len) + 32 (raw sha256) + 16 (magic)

const VALID_OS = new Set(['windows', 'macos', 'linux']);
const VALID_ARCH = new Set(['arm64', 'x64']);

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function sha256Raw(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

export function validateRelativeEntryName(rawName) {
  if (typeof rawName !== 'string' || rawName.length === 0) {
    throw new Error('Package entry name must be a non-empty string');
  }
  if (rawName.includes('\0')) {
    throw new Error(`Invalid NUL byte in entry name: ${JSON.stringify(rawName)}`);
  }
  if (rawName.startsWith('/') || rawName.startsWith('\\')) {
    throw new Error(`Absolute leading slash forbidden in entry name: ${rawName}`);
  }
  if (rawName.includes(':')) {
    throw new Error(`Drive letter or colon forbidden in entry name: ${rawName}`);
  }
  const normalized = rawName.replace(/\\/g, '/');
  const segments = normalized.split('/');
  for (const seg of segments) {
    if (!seg || seg === '.' || seg === '..') {
      throw new Error(`Unsafe path segment in entry name: ${rawName}`);
    }
  }
  return segments.join('/');
}

function inferPosixMode(entryName, srcPath, targetOs, explicitMode) {
  if (Number.isInteger(explicitMode) && explicitMode > 0) {
    return explicitMode;
  }
  const lower = entryName.toLowerCase();
  if (lower.endsWith('.exe') || lower.endsWith('.dll') || lower.endsWith('.sh') || lower.endsWith('.run')) {
    return 0o755; // 493
  }
  if (targetOs !== 'windows') {
    const base = path.posix.basename(lower);
    if (base === 'alluse' || base === 'alluse-setup' || lower.startsWith('contents/macos/')) {
      return 0o755;
    }
  }
  try {
    const st = fs.statSync(srcPath);
    if (process.platform !== 'win32' && (st.mode & 0o111) !== 0) {
      return 0o755;
    }
  } catch {
    // Ignore stat fallback when buffer-only inputs are used
  }
  return 0o644; // 420
}

export function collectInputEntries(inputSpecs = [], inputDir = '') {
  const entries = [];
  const seen = new Set();

  if (inputDir) {
    const absDir = path.resolve(inputDir);
    const walk = (dir) => {
      const dirents = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
      for (const d of dirents) {
        const full = path.join(dir, d.name);
        if (d.isDirectory()) {
          walk(full);
        } else if (d.isFile()) {
          const rel = validateRelativeEntryName(path.relative(absDir, full));
          if (seen.has(rel)) {
            throw new Error(`Duplicate package entry name: ${rel}`);
          }
          seen.add(rel);
          entries.push({ srcPath: full, name: rel });
        }
      }
    };
    walk(absDir);
  }

  for (const spec of inputSpecs) {
    if (typeof spec === 'string') {
      // Split on last ':' that does not look like a Windows drive prefix (e.g. C:\foo\bar)
      let srcPath = spec;
      let destName = '';
      const lastColon = spec.lastIndexOf(':');
      if (lastColon > 1) {
        srcPath = spec.slice(0, lastColon);
        destName = spec.slice(lastColon + 1);
      }
      const absSrc = path.resolve(srcPath);
      const name = validateRelativeEntryName(destName || path.basename(absSrc));
      if (seen.has(name)) {
        throw new Error(`Duplicate package entry name: ${name}`);
      }
      seen.add(name);
      entries.push({ srcPath: absSrc, name });
    } else if (spec && typeof spec === 'object') {
      const name = validateRelativeEntryName(spec.name);
      if (seen.has(name)) {
        throw new Error(`Duplicate package entry name: ${name}`);
      }
      seen.add(name);
      entries.push({
        srcPath: spec.srcPath ? path.resolve(spec.srcPath) : '',
        name,
        data: spec.data,
        mode: spec.mode,
      });
    }
  }

  return entries;
}

export function buildPayloadBytes({ version, os: targetOs, arch, entries }) {
  const cleanVersion = String(version || '').replace(/^v/i, '').trim();
  if (!cleanVersion) {
    throw new Error('buildPayloadBytes requires non-empty version');
  }
  if (!VALID_OS.has(targetOs)) {
    throw new Error(`Unsupported package os: ${targetOs}`);
  }
  if (!VALID_ARCH.has(arch)) {
    throw new Error(`Unsupported package arch: ${arch}`);
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('buildPayloadBytes requires at least one file entry');
  }

  const fileRecords = [];
  const rawChunks = [];
  let offset = 0;

  for (const entry of entries) {
    const safeName = validateRelativeEntryName(entry.name);
    const data = Buffer.isBuffer(entry.data)
      ? entry.data
      : fs.readFileSync(entry.srcPath);
    const mode = inferPosixMode(safeName, entry.srcPath || '', targetOs, entry.mode);
    const sha256 = sha256Hex(data);
    fileRecords.push({
      name: safeName,
      offset,
      size: data.length,
      mode,
      sha256,
    });
    rawChunks.push(data);
    offset += data.length;
  }

  const manifestObj = {
    format: PACKAGE_FORMAT,
    version: cleanVersion,
    os: targetOs,
    arch,
    files: fileRecords,
  };
  const manifestBuf = Buffer.from(JSON.stringify(manifestObj), 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(manifestBuf.length, 0);

  const uncompressed = Buffer.concat([lenBuf, manifestBuf, ...rawChunks]);
  const gzBuf = zlib.gzipSync(uncompressed, { level: 9 });
  const gzShaRaw = sha256Raw(gzBuf);
  if (gzShaRaw.length !== 32) {
    throw new Error(`Expected 32-byte sha256 digest, got ${gzShaRaw.length}`);
  }

  const footer = Buffer.alloc(FOOTER_SIZE);
  footer.writeBigUInt64LE(BigInt(gzBuf.length), 0);
  gzShaRaw.copy(footer, 8);
  PACKAGE_MAGIC.copy(footer, 40);

  return {
    payloadBytes: Buffer.concat([gzBuf, footer]),
    manifest: manifestObj,
    gzSize: gzBuf.length,
    uncompressedSize: uncompressed.length,
  };
}

export function verifyPayloadBuffer(containerBuf) {
  if (!Buffer.isBuffer(containerBuf) || containerBuf.length < FOOTER_SIZE) {
    throw new Error('Container smaller than 56-byte ALLUSE_PKG_V1 footer');
  }
  const footerStart = containerBuf.length - FOOTER_SIZE;
  const footer = containerBuf.subarray(footerStart);
  const magic = footer.subarray(40, 56);
  if (!magic.equals(PACKAGE_MAGIC)) {
    throw new Error('Missing ALLUSE_PKG_V1 trailer magic');
  }

  const gzLenBig = footer.readBigUInt64LE(0);
  if (gzLenBig <= 0n || gzLenBig > BigInt(footerStart)) {
    throw new Error(`Invalid compressed payload length: ${gzLenBig.toString()}`);
  }
  const gzLen = Number(gzLenBig);
  const gzStart = footerStart - gzLen;
  const gzSlice = containerBuf.subarray(gzStart, footerStart);

  const expectedGzSha = footer.subarray(8, 40);
  const actualGzSha = sha256Raw(gzSlice);
  if (!actualGzSha.equals(expectedGzSha)) {
    throw new Error('Compressed payload SHA-256 verification failed');
  }

  const uncompressed = zlib.gunzipSync(gzSlice);
  if (uncompressed.length < 4) {
    throw new Error('Corrupt uncompressed archive: missing manifest_len');
  }
  const manifestLen = uncompressed.readUInt32LE(0);
  if (4 + manifestLen > uncompressed.length) {
    throw new Error('Corrupt uncompressed archive: manifest exceeds buffer bounds');
  }
  const manifest = JSON.parse(uncompressed.subarray(4, 4 + manifestLen).toString('utf8'));
  if (manifest.format !== PACKAGE_FORMAT) {
    throw new Error(`Unexpected manifest format: ${manifest.format}`);
  }
  if (!VALID_OS.has(manifest.os) || !VALID_ARCH.has(manifest.arch)) {
    throw new Error(`Invalid manifest target: ${manifest.os}/${manifest.arch}`);
  }

  const rawArea = uncompressed.subarray(4 + manifestLen);
  const extracted = new Map();
  for (const file of manifest.files || []) {
    const safeName = validateRelativeEntryName(file.name);
    if (!Number.isInteger(file.offset) || !Number.isInteger(file.size) || file.offset < 0 || file.size < 0) {
      throw new Error(`Invalid bounds for file ${safeName}`);
    }
    if (file.offset + file.size > rawArea.length) {
      throw new Error(`File ${safeName} exceeds raw data bounds`);
    }
    const content = rawArea.subarray(file.offset, file.offset + file.size);
    const actualSha = sha256Hex(content);
    if (actualSha !== String(file.sha256 || '').toLowerCase()) {
      throw new Error(`SHA-256 mismatch for extracted file ${safeName}`);
    }
    extracted.set(safeName, content);
  }

  return {
    stubLength: gzStart,
    gzLength: gzLen,
    manifest,
    extracted,
  };
}

export function packageInstaller({
  version,
  os: targetOs,
  arch,
  entries,
  outPath,
  stubPath = '',
  payloadOnly = false,
}) {
  const built = buildPayloadBytes({ version, os: targetOs, arch, entries });
  const absOut = path.resolve(outPath);
  fs.mkdirSync(path.dirname(absOut), { recursive: true });

  if (payloadOnly) {
    fs.writeFileSync(absOut, built.payloadBytes);
  } else {
    if (!stubPath) {
      throw new Error('packageInstaller requires --stub unless --payload-only is set');
    }
    const stubBytes = fs.readFileSync(path.resolve(stubPath));
    fs.writeFileSync(absOut, Buffer.concat([stubBytes, built.payloadBytes]));
    if (targetOs !== 'windows' && process.platform !== 'win32') {
      fs.chmodSync(absOut, 0o755);
    }
  }

  return {
    outPath: absOut,
    bytes: fs.statSync(absOut).size,
    ...built,
  };
}

function renderMacosInfoPlist(version) {
  const escapedVersion = String(version).replace(/[<>&"']/g, '');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>CheapAI AllUse Setup</string>
  <key>CFBundleExecutable</key>
  <string>alluse-setup</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon.icns</string>
  <key>CFBundleIdentifier</key>
  <string>im.cheapai.alluse.setup</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>CheapAI AllUse Setup</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${escapedVersion}</string>
  <key>CFBundleVersion</key>
  <string>${escapedVersion}</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
`;
}

export function packageMacosApp({
  version,
  arch,
  entries,
  appDir,
  stubPath,
  iconPath = '',
}) {
  const absApp = path.resolve(appDir);
  const contentsDir = path.join(absApp, 'Contents');
  const macosDir = path.join(contentsDir, 'MacOS');
  const resourcesDir = path.join(contentsDir, 'Resources');

  fs.rmSync(absApp, { recursive: true, force: true });
  fs.mkdirSync(macosDir, { recursive: true });
  fs.mkdirSync(resourcesDir, { recursive: true });

  const cleanVersion = String(version).replace(/^v/i, '').trim();
  fs.writeFileSync(path.join(contentsDir, 'Info.plist'), renderMacosInfoPlist(cleanVersion), 'utf8');

  const setupDst = path.join(macosDir, 'alluse-setup');
  fs.copyFileSync(path.resolve(stubPath), setupDst);
  if (process.platform !== 'win32') {
    fs.chmodSync(setupDst, 0o755);
  }

  if (iconPath && fs.existsSync(iconPath)) {
    fs.copyFileSync(path.resolve(iconPath), path.join(resourcesDir, 'AppIcon.icns'));
  }

  const payloadOut = path.join(resourcesDir, 'payload.pak');
  const built = packageInstaller({
    version: cleanVersion,
    os: 'macos',
    arch,
    entries,
    outPath: payloadOut,
    payloadOnly: true,
  });

  return {
    appDir: absApp,
    payloadPath: payloadOut,
    manifest: built.manifest,
  };
}

export function writeSha256Sums(dirPath) {
  const absDir = path.resolve(dirPath);
  const entries = fs.readdirSync(absDir, { withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => d.name)
    .filter((name) => name !== 'SHA256SUMS.txt' && name !== 'updates-manifest.json')
    .sort();
  const lines = entries.map((name) => `${sha256Hex(fs.readFileSync(path.join(absDir, name)))}  ${name}`);
  const out = path.join(absDir, 'SHA256SUMS.txt');
  const text = lines.length > 0 ? `${lines.join('\n')}\n` : '';
  fs.writeFileSync(out, text, 'utf8');
  return { path: out, count: lines.length };
}

function assert(cond, msg) {
  if (!cond) {
    throw new Error(`Assertion failed: ${msg}`);
  }
}

function runSelfTest() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alluse-pkg-test-'));
  try {
    const stubBytes = Buffer.from('FAKE_PE_OR_ELF_STUB_0123456789ABCDEF');
    const stubPath = path.join(tmpDir, 'alluse-setup-stub.exe');
    fs.writeFileSync(stubPath, stubBytes);

    const exeBytes = Buffer.from('MZ_TEST_ALLUSE_BINARY_PAYLOAD');
    const dllBytes = Buffer.from('WEBVIEW2_LOADER_BYTES');
    const iconBytes = Buffer.from('\x00\x00\x01\x00ICON_DATA');

    const winEntries = [
      { name: 'alluse.exe', data: exeBytes, mode: 0o755 },
      { name: 'WebView2Loader.dll', data: dllBytes, mode: 0o755 },
      { name: 'nested/alluse.ico', data: iconBytes, mode: 0o644 },
    ];

    // 1. Appended installer roundtrip
    const winOut = path.join(tmpDir, 'dist', 'AllUse-Setup-1.0.0-win32-arm64.exe');
    packageInstaller({
      version: '1.0.0',
      os: 'windows',
      arch: 'arm64',
      entries: winEntries,
      outPath: winOut,
      stubPath,
    });
    const fullWinBuf = fs.readFileSync(winOut);
    const verifiedWin = verifyPayloadBuffer(fullWinBuf);
    assert(verifiedWin.stubLength === stubBytes.length, 'stub length preserved');
    assert(fullWinBuf.subarray(0, verifiedWin.stubLength).equals(stubBytes), 'stub bytes exact match');
    assert(verifiedWin.manifest.format === 'alluse-pkg-v1', 'manifest format exact');
    assert(verifiedWin.manifest.os === 'windows' && verifiedWin.manifest.arch === 'arm64', 'manifest target match');
    assert(verifiedWin.extracted.get('alluse.exe').equals(exeBytes), 'extracted alluse.exe exact');
    assert(verifiedWin.extracted.get('nested/alluse.ico').equals(iconBytes), 'extracted nested entry exact');
    assert(verifiedWin.manifest.files[0].mode === 493, 'executable mode 0o755 == 493');

    // 2. Standalone payload.pak
    const pakOut = path.join(tmpDir, 'payload.pak');
    packageInstaller({
      version: '1.0.0',
      os: 'linux',
      arch: 'x64',
      entries: [{ name: 'alluse', data: exeBytes }],
      outPath: pakOut,
      payloadOnly: true,
    });
    const verifiedPak = verifyPayloadBuffer(fs.readFileSync(pakOut));
    assert(verifiedPak.stubLength === 0, 'standalone payload stub length == 0');
    assert(verifiedPak.manifest.files[0].mode === 493, 'unix alluse binary defaults to 0o755');

    // 3. macOS .app staging + SHA256SUMS
    const fakeIcns = path.join(tmpDir, 'AppIcon.icns');
    fs.writeFileSync(fakeIcns, 'icnsFAKE');
    const appDir = path.join(tmpDir, 'dist', 'AllUse Installer.app');
    const appRes = packageMacosApp({
      version: '1.0.0',
      arch: 'x64',
      entries: [{ name: 'alluse', data: exeBytes }],
      appDir,
      stubPath,
      iconPath: fakeIcns,
    });
    assert(fs.existsSync(path.join(appDir, 'Contents', 'Info.plist')), 'Info.plist exists');
    assert(fs.existsSync(path.join(appDir, 'Contents', 'MacOS', 'alluse-setup')), 'MacOS setup exists');
    assert(fs.existsSync(path.join(appDir, 'Contents', 'Resources', 'AppIcon.icns')), 'AppIcon.icns exists');
    const verifiedAppPak = verifyPayloadBuffer(fs.readFileSync(appRes.payloadPath));
    assert(verifiedAppPak.manifest.os === 'macos' && verifiedAppPak.manifest.arch === 'x64', 'macOS x64 manifest exact');

    const sumsRes = writeSha256Sums(path.join(tmpDir, 'dist'));
    assert(sumsRes.count === 1 && fs.existsSync(sumsRes.path), 'SHA256SUMS.txt created');

    // 4. Negative integrity tests: tamper compressed byte & path traversal
    const tampered = Buffer.from(fullWinBuf);
    tampered[stubBytes.length + 5] ^= 0xff;
    let tamperRejected = false;
    try {
      verifyPayloadBuffer(tampered);
    } catch {
      tamperRejected = true;
    }
    assert(tamperRejected, 'tampered gzip payload rejected');

    for (const badPath of ['../evil.exe', '/etc/passwd', '\\Windows\\cmd.exe', 'C:\\bad.exe', 'a\0b', '.']) {
      let rejected = false;
      try {
        validateRelativeEntryName(badPath);
      } catch {
        rejected = true;
      }
      assert(rejected, `unsafe path rejected: ${JSON.stringify(badPath)}`);
    }

    console.log('package-installer self-test ok');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    runSelfTest();
    return;
  }

  const verifyIdx = args.indexOf('--verify');
  if (verifyIdx >= 0) {
    const targetFile = args[verifyIdx + 1];
    if (!targetFile) {
      throw new Error('--verify requires a file path');
    }
    const res = verifyPayloadBuffer(fs.readFileSync(path.resolve(targetFile)));
    console.log(JSON.stringify({
      ok: true,
      stubLength: res.stubLength,
      gzLength: res.gzLength,
      manifest: res.manifest,
    }, null, 2));
    return;
  }

  const checksumsIdx = args.indexOf('--checksums');
  if (checksumsIdx >= 0) {
    const dir = args[checksumsIdx + 1];
    if (!dir) {
      throw new Error('--checksums requires a directory path');
    }
    const res = writeSha256Sums(dir);
    console.log(`Generated ${res.path} (${res.count} entries)`);
    return;
  }

  const inputs = [];
  let inputDir = '';
  let targetOs = '';
  let arch = '';
  let version = '';
  let stubPath = '';
  let outPath = '';
  let iconPath = '';
  let checksumsDir = '';
  let payloadOnly = false;
  let macosApp = false;

  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--os') targetOs = args[++i] || '';
    else if (a === '--arch') arch = args[++i] || '';
    else if (a === '--version') version = args[++i] || '';
    else if (a === '--stub') stubPath = args[++i] || '';
    else if (a === '--out') outPath = args[++i] || '';
    else if (a === '--icon') iconPath = args[++i] || '';
    else if (a === '--input') inputs.push(args[++i] || '');
    else if (a === '--input-dir') inputDir = args[++i] || '';
    else if (a === '--checksums-dir') checksumsDir = args[++i] || '';
    else if (a === '--payload-only') payloadOnly = true;
    else if (a === '--macos-app') macosApp = true;
    else throw new Error(`Unknown argument: ${a}`);
  }

  if (!version) {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    version = pkg.version;
  }
  const entries = collectInputEntries(inputs, inputDir);

  if (macosApp) {
    const res = packageMacosApp({
      version,
      arch,
      entries,
      appDir: outPath,
      stubPath,
      iconPath,
    });
    console.log(`Staged macOS installer app: ${res.appDir} (${res.manifest.files.length} payload files)`);
  } else {
    const res = packageInstaller({
      version,
      os: targetOs,
      arch,
      entries,
      outPath,
      stubPath,
      payloadOnly,
    });
    console.log(`Packaged ${res.outPath} (${res.bytes} bytes, ${res.manifest.files.length} files)`);
  }

  if (checksumsDir) {
    const sums = writeSha256Sums(checksumsDir);
    console.log(`Updated ${sums.path} (${sums.count} entries)`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
