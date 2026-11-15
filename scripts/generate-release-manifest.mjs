#!/usr/bin/env node
/**
 * Generate `updates-manifest.json` and `SHA256SUMS.txt` across all 6 CheapAI AllUse release targets:
 *   - darwin.arm64  (`aarch64-apple-darwin`, `.dmg` primary / `.app.tar.gz` fallback)
 *   - darwin.x64    (`x86_64-apple-darwin`, `.dmg` primary / `.app.tar.gz` fallback)
 *   - win32.arm64   (`aarch64-pc-windows-gnullvm`, `AllUse-Setup-<ver>-win32-arm64.exe`)
 *   - win32.x64     (`x86_64-pc-windows-gnullvm`, `AllUse-Setup-<ver>-win32-x64.exe`)
 *   - linux.x64     (`x86_64-unknown-linux-gnu`, `.run` primary / `.tar.gz` fallback)
 *   - linux.arm64   (`aarch64-unknown-linux-gnu`, `.run` primary / `.tar.gz` fallback)
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

export const SUPPORTED_RELEASE_TARGETS = [
  { os: 'darwin', arch: 'arm64', triple: 'aarch64-apple-darwin', ext: '.dmg' },
  { os: 'darwin', arch: 'x64', triple: 'x86_64-apple-darwin', ext: '.dmg' },
  { os: 'win32', arch: 'arm64', triple: 'aarch64-pc-windows-gnullvm', ext: '.exe' },
  { os: 'win32', arch: 'x64', triple: 'x86_64-pc-windows-gnullvm', ext: '.exe' },
  { os: 'linux', arch: 'x64', triple: 'x86_64-unknown-linux-gnu', ext: '.run' },
  { os: 'linux', arch: 'arm64', triple: 'aarch64-unknown-linux-gnu', ext: '.run' },
];

export function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

export function classifyArtifact(fileName) {
  const lower = fileName.toLowerCase();
  if (
    lower === 'sha256sums.txt' ||
    lower === 'updates-manifest.json' ||
    lower.endsWith('.sha256') ||
    lower.endsWith('.sig') ||
    lower.endsWith('.dll') ||
    lower.endsWith('.txt') ||
    lower.endsWith('.md') ||
    lower.endsWith('.json')
  ) {
    return null;
  }

  let targetOs = null;
  if (lower.endsWith('.dmg') || lower.endsWith('.app.tar.gz') || lower.includes('darwin') || lower.includes('macos')) {
    targetOs = 'darwin';
  } else if (lower.endsWith('.exe') || lower.endsWith('.msi') || lower.endsWith('.zip') || lower.includes('win32') || lower.includes('windows')) {
    targetOs = 'win32';
  } else if (lower.endsWith('.run') || lower.endsWith('.appimage') || lower.endsWith('.deb') || lower.endsWith('.rpm') || lower.includes('linux')) {
    targetOs = 'linux';
  }

  let arch = null;
  if (lower.includes('arm64') || lower.includes('aarch64') || lower.includes('apple-silicon')) {
    arch = 'arm64';
  } else if (lower.includes('x64') || lower.includes('x86_64') || lower.includes('amd64') || lower.includes('intel')) {
    arch = 'x64';
  }

  // Explicitly exclude arch-less default copy (e.g. `AllUse-Setup-1.0.0.exe`) from target slots
  if (!targetOs || !arch) {
    return null;
  }

  let priority = 0;
  let isPrimaryUpdaterAsset = false;

  if (targetOs === 'darwin') {
    if (lower.endsWith('.dmg')) {
      priority = 30;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.app.tar.gz')) {
      priority = 20;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.tar.gz') || lower.endsWith('.zip')) {
      priority = 10;
      isPrimaryUpdaterAsset = true;
    }
  } else if (targetOs === 'win32') {
    if (lower.endsWith('.exe') && (lower.includes('setup') || lower.includes('installer'))) {
      priority = 30;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.msi')) {
      priority = 25;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.zip')) {
      priority = 15;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.exe')) {
      priority = 5;
      isPrimaryUpdaterAsset = true;
    }
  } else if (targetOs === 'linux') {
    if (lower.endsWith('.run')) {
      priority = 30;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.appimage')) {
      priority = 25;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.deb') || lower.endsWith('.rpm')) {
      priority = 20;
      isPrimaryUpdaterAsset = true;
    } else if (lower.endsWith('.tar.gz')) {
      priority = 10;
      isPrimaryUpdaterAsset = true;
    }
  }

  if (!isPrimaryUpdaterAsset) {
    return null;
  }

  return { os: targetOs, arch, priority, isPrimaryUpdaterAsset };
}

export function buildReleaseManifest({
  version,
  baseUrl,
  artifactsDir,
  releaseNotes = '',
  mandatory = false,
}) {
  const cleanVersion = String(version || '').replace(/^v/i, '').trim();
  if (!cleanVersion) {
    throw new Error('buildReleaseManifest requires a non-empty version');
  }
  const normalizedBaseUrl = String(baseUrl || `https://github.com/akitect45/cheapai-alluse/releases/download/v${cleanVersion}`).replace(/\/+$/, '');

  const files = {
    darwin: {},
    win32: {},
    linux: {},
  };
  const slotPriorities = new Map();
  const checksumLines = [];

  const entries = fs.existsSync(artifactsDir)
    ? fs.readdirSync(artifactsDir, { withFileTypes: true })
    : [];

  const sortedFiles = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => name !== 'SHA256SUMS.txt' && name !== 'updates-manifest.json')
    .sort();

  for (const fileName of sortedFiles) {
    const fullPath = path.join(artifactsDir, fileName);
    const stat = fs.statSync(fullPath);
    const sha256 = sha256File(fullPath);
    checksumLines.push(`${sha256}  ${fileName}`);

    const info = classifyArtifact(fileName);
    if (!info || !info.isPrimaryUpdaterAsset) {
      continue;
    }

    const slotKey = `${info.os}.${info.arch}`;
    const prevPriority = slotPriorities.get(slotKey) ?? -1;
    if (info.priority <= prevPriority) {
      continue;
    }
    slotPriorities.set(slotKey, info.priority);

    const url = `${normalizedBaseUrl}/${encodeURIComponent(fileName)}`;
    files[info.os][info.arch] = {
      url,
      sha256,
      size: stat.size,
      fileName,
    };
  }

  const primaryDefault = files.win32.arm64 || files.win32.x64 || files.darwin.arm64 || files.linux.x64 || null;
  const manifest = {
    productName: 'CheapAI AllUse',
    name: 'alluse',
    latestVersion: cleanVersion,
    version: cleanVersion,
    releaseNotes,
    mandatory: Boolean(mandatory),
    supportedTargets: SUPPORTED_RELEASE_TARGETS.map((t) => t.triple),
    downloadUrl: primaryDefault ? primaryDefault.url : '',
    sha256: primaryDefault ? primaryDefault.sha256 : '',
    files,
  };

  return {
    manifest,
    checksumsText: checksumLines.length ? `${checksumLines.join('\n')}\n` : '',
  };
}

function assert(cond, msg) {
  if (!cond) {
    throw new Error(`Assertion failed: ${msg}`);
  }
}

function runSelfTest() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alluse-manifest-test-'));
  try {
    // Case 1: Full 6-target set + fallback lower-priority archives + default arch-less Windows copy
    const fullSetDir = path.join(tmpDir, 'full');
    fs.mkdirSync(fullSetDir, { recursive: true });
    const dummyFiles = [
      'AllUse-Setup-1.0.0.exe', // must stay in SHA256SUMS.txt without overwriting win32 slots
      'AllUse-Setup-1.0.0-win32-arm64.exe',
      'AllUse-Setup-1.0.0-win32-x64.exe',
      'alluse-win32-x64.exe',
      'AllUse-Setup-1.0.0-darwin-arm64.app.tar.gz',
      'AllUse-Setup-1.0.0-darwin-arm64.dmg',
      'AllUse-Setup-1.0.0-darwin-x64.app.tar.gz',
      'AllUse-Setup-1.0.0-darwin-x64.dmg',
      'AllUse-Setup-1.0.0-linux-x64.run',
      'alluse-1.0.0-linux-x64.tar.gz',
      'AllUse-Setup-1.0.0-linux-arm64.run',
      'alluse-1.0.0-linux-arm64.tar.gz',
    ];
    for (const name of dummyFiles) {
      fs.writeFileSync(path.join(fullSetDir, name), `dummy-${name}`, 'utf8');
    }

    const { manifest, checksumsText } = buildReleaseManifest({
      version: '1.0.0',
      baseUrl: 'https://github.com/akitect45/cheapai-alluse/releases/download/v1.0.0',
      artifactsDir: fullSetDir,
      releaseNotes: '6-target AllUse custom installer release',
    });

    assert(manifest.latestVersion === '1.0.0', 'latestVersion matches');
    assert(manifest.supportedTargets.length === 6, '6 supportedTargets');
    assert(manifest.files.darwin.arm64?.fileName === 'AllUse-Setup-1.0.0-darwin-arm64.dmg', 'darwin.arm64 prefers .dmg');
    assert(manifest.files.darwin.x64?.fileName === 'AllUse-Setup-1.0.0-darwin-x64.dmg', 'darwin.x64 includes Intel macOS & prefers .dmg');
    assert(manifest.files.win32.arm64?.fileName === 'AllUse-Setup-1.0.0-win32-arm64.exe', 'win32.arm64 setup chosen');
    assert(manifest.files.win32.x64?.fileName === 'AllUse-Setup-1.0.0-win32-x64.exe', 'win32.x64 setup beats raw binary');
    assert(manifest.files.linux.x64?.fileName === 'AllUse-Setup-1.0.0-linux-x64.run', 'linux.x64 prefers .run');
    assert(manifest.files.linux.arm64?.fileName === 'AllUse-Setup-1.0.0-linux-arm64.run', 'linux.arm64 prefers .run');
    assert(checksumsText.includes('  AllUse-Setup-1.0.0.exe\n'), 'archless exe present in SHA256SUMS');
    assert(checksumsText.trim().split('\n').length === dummyFiles.length, 'every file checksummed');

    // Case 2: Fallback assets (.app.tar.gz / .tar.gz) when .dmg / .run are absent
    const fallbackDir = path.join(tmpDir, 'fallback');
    fs.mkdirSync(fallbackDir, { recursive: true });
    for (const name of [
      'AllUse-Setup-1.0.0-darwin-arm64.app.tar.gz',
      'AllUse-Setup-1.0.0-darwin-x64.app.tar.gz',
      'alluse-1.0.0-linux-x64.tar.gz',
      'alluse-1.0.0-linux-arm64.tar.gz',
    ]) {
      fs.writeFileSync(path.join(fallbackDir, name), `fb-${name}`, 'utf8');
    }
    const fb = buildReleaseManifest({ version: '1.0.0', artifactsDir: fallbackDir }).manifest;
    assert(fb.files.darwin.arm64?.fileName === 'AllUse-Setup-1.0.0-darwin-arm64.app.tar.gz', 'darwin.arm64 fallback works');
    assert(fb.files.darwin.x64?.fileName === 'AllUse-Setup-1.0.0-darwin-x64.app.tar.gz', 'darwin.x64 fallback works');
    assert(fb.files.linux.x64?.fileName === 'alluse-1.0.0-linux-x64.tar.gz', 'linux.x64 fallback works');
    assert(fb.files.linux.arm64?.fileName === 'alluse-1.0.0-linux-arm64.tar.gz', 'linux.arm64 fallback works');

    console.log('generate-release-manifest self-test ok');
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

  const getArg = (flag, fallback = '') => {
    const idx = args.indexOf(flag);
    return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : fallback;
  };

  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const version = getArg('--version', process.env.RELEASE_VERSION || pkg.version);
  const artifactsDir = path.resolve(getArg('--dir', process.env.ARTIFACTS_DIR || path.join(ROOT, 'dist')));
  const baseUrl = getArg(
    '--base-url',
    process.env.RELEASE_BASE_URL || `https://github.com/akitect45/cheapai-alluse/releases/download/v${String(version).replace(/^v/i, '')}`,
  );
  const notesFile = getArg('--notes-file', '');
  const releaseNotes = notesFile && fs.existsSync(notesFile) ? fs.readFileSync(notesFile, 'utf8') : '';

  fs.mkdirSync(artifactsDir, { recursive: true });
  const { manifest, checksumsText } = buildReleaseManifest({
    version,
    baseUrl,
    artifactsDir,
    releaseNotes,
  });

  const manifestPath = path.join(artifactsDir, 'updates-manifest.json');
  const checksumsPath = path.join(artifactsDir, 'SHA256SUMS.txt');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  fs.writeFileSync(checksumsPath, checksumsText, 'utf8');
  console.log(`Generated ${manifestPath} and ${checksumsPath}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
