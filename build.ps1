param(
    [ValidateSet("arm64", "x64", "all", "auto")]
    [string]$Arch = "auto",
    [ValidateSet("gnullvm", "msvc")]
    [string]$Toolchain = "gnullvm",
    [switch]$CargoOnly,
    [string]$Version = ""
)

# Build CheapAI AllUse & custom native installer (`alluse` + `alluse-setup`) for Windows.
# Uses `--target <triple>` so existing `target\release\alluse.exe` is never overwritten.
#
# Examples:
#   .\build.ps1
#   .\build.ps1 -Arch arm64
#   .\build.ps1 -Arch x64
#   .\build.ps1 -Arch all
#   .\build.ps1 -Arch arm64 -Toolchain msvc
#   .\build.ps1 -Arch arm64 -CargoOnly

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

function Resolve-HostArch {
    $candidates = @()
    if ($env:PROCESSOR_ARCHITEW6432) { $candidates += $env:PROCESSOR_ARCHITEW6432 }
    if ($env:PROCESSOR_ARCHITECTURE) { $candidates += $env:PROCESSOR_ARCHITECTURE }
    try {
        $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        if ($osArch) { $candidates += $osArch }
    } catch {}
    foreach ($c in $candidates) {
        $u = $c.ToUpperInvariant()
        if ($u -like "*ARM64*" -or $u -like "*AARCH64*") { return "arm64" }
    }
    return "x64"
}

function Resolve-PackageVersion([string]$OverrideVersion) {
    if ($OverrideVersion) {
        return ($OverrideVersion.Trim() -replace '^[vV]', '')
    }
    $cargoToml = Join-Path $ProjectRoot "Cargo.toml"
    if (Test-Path $cargoToml) {
        $match = Select-String -Path $cargoToml -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($match) {
            return $match.Matches[0].Groups[1].Value
        }
    }
    $pkgJson = Join-Path $ProjectRoot "package.json"
    if (Test-Path $pkgJson) {
        $pkg = Get-Content -Raw $pkgJson | ConvertFrom-Json
        if ($pkg.version) { return [string]$pkg.version }
    }
    return "1.0.0"
}

function Get-CandidateHomes {
    $userHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
    $profileDirs = @()
    if (Test-Path "C:\Users") {
        $profileDirs = @(
            Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                Where-Object {
                    (Test-Path (Join-Path $_.FullName ".cargo\bin\cargo.exe")) -or
                    (Test-Path (Join-Path $_.FullName ".llvm-mingw\bin"))
                } |
                Select-Object -ExpandProperty FullName
        )
    }
    $raw = @($userHome, $HOME, $(if ($env:USERNAME) { "C:\Users\$($env:USERNAME)" } else { $null })) + $profileDirs
    return @($raw | Where-Object { $_ } | Select-Object -Unique)
}

function Find-VcVarsAll {
    $editions = @("BuildTools", "Community", "Professional", "Enterprise")
    foreach ($vsRoot in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $vsRoot) { continue }
        foreach ($ver in @("2022", "18")) {
            foreach ($edition in $editions) {
                $candidate = Join-Path $vsRoot "Microsoft Visual Studio\$ver\$edition\VC\Auxiliary\Build\vcvarsall.bat"
                if (Test-Path $candidate) { return $candidate }
            }
        }
    }
    return $null
}

function Get-TargetTriple([string]$TargetArch, [string]$Tool) {
    if ($Tool -eq "msvc") {
        if ($TargetArch -eq "arm64") { return "aarch64-pc-windows-msvc" }
        return "x86_64-pc-windows-msvc"
    }
    if ($TargetArch -eq "arm64") { return "aarch64-pc-windows-gnullvm" }
    return "x86_64-pc-windows-gnullvm"
}

function Get-MingwTriple([string]$TargetArch) {
    if ($TargetArch -eq "arm64") { return "aarch64-w64-mingw32" }
    return "x86_64-w64-mingw32"
}

function Find-WebView2Loader([string]$Triple, [string]$TargetArch, [string]$HostArch) {
    $archDir = if ($TargetArch -eq "arm64") { "arm64" } else { "x64" }
    $direct = Join-Path $ProjectRoot "target\$Triple\release\WebView2Loader.dll"
    if (Test-Path $direct) { return $direct }

    $buildSearchRoots = @(
        (Join-Path $ProjectRoot "target\$Triple\release\build"),
        (Join-Path $ProjectRoot "target\release\build"),
        (Join-Path $ProjectRoot "target\debug\build")
    )
    foreach ($rootDir in $buildSearchRoots) {
        if (-not (Test-Path $rootDir)) { continue }
        $found = Get-ChildItem -Path $rootDir -Recurse -Filter "WebView2Loader.dll" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\out\$archDir\WebView2Loader.dll" } |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    if ($TargetArch -eq $HostArch) {
        $bak = Join-Path $ProjectRoot "data\backups\dlls\WebView2Loader.dll"
        if (Test-Path $bak) { return $bak }
    }
    return $null
}

function Find-LibUnwind([string]$Triple, [string]$MingwTriple, [string[]]$Homes, [string]$TargetArch, [string]$HostArch) {
    $direct = Join-Path $ProjectRoot "target\$Triple\release\libunwind.dll"
    if (Test-Path $direct) { return $direct }

    foreach ($h in $Homes) {
        $cand = Join-Path $h ".llvm-mingw\$MingwTriple\bin\libunwind.dll"
        if (Test-Path $cand) { return $cand }
    }

    if ($TargetArch -eq $HostArch) {
        $bak = Join-Path $ProjectRoot "data\backups\dlls\libunwind.dll"
        if (Test-Path $bak) { return $bak }
    }
    return $null
}

function Find-LlvmLicense([string[]]$Homes) {
    foreach ($h in $Homes) {
        $cand = Join-Path $h ".llvm-mingw\LICENSE.TXT"
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

$CandidateHomes = Get-CandidateHomes
foreach ($h in $CandidateHomes) {
    $cDir = Join-Path $h ".cargo"
    $rDir = Join-Path $h ".rustup"
    if ((Test-Path (Join-Path $cDir "bin\cargo.exe")) -and (-not $env:CARGO_HOME)) { $env:CARGO_HOME = $cDir }
    if ((Test-Path (Join-Path $rDir "settings.toml")) -and (-not $env:RUSTUP_HOME)) { $env:RUSTUP_HOME = $rDir }
    $cargoBin = Join-Path $cDir "bin"
    if ((Test-Path $cargoBin) -and ($env:PATH -notlike "*$cargoBin*")) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo was not found in PATH. Install Rust via https://rustup.rs/."
}

$HostArch = Resolve-HostArch
$ResolvedVersion = Resolve-PackageVersion $Version
$TargetArches = switch ($Arch) {
    "all" { @("arm64", "x64") }
    "auto" { @($HostArch) }
    default { @($Arch) }
}

Write-Host "[AllUse Build] HostArch=$HostArch, Targets=$($TargetArches -join ','), Toolchain=$Toolchain, Version=$ResolvedVersion" -ForegroundColor Cyan

$OriginalPath = $env:PATH
$DistWinDir = Join-Path $ProjectRoot "dist\windows"
$IconsDir = Join-Path $ProjectRoot "target\installer-icons"
$BuiltInstallers = @{}

if (-not $CargoOnly) {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw "Node.js >= 18 is required to package ALLUSE_PKG_V1 installers (or pass -CargoOnly)."
    }
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $pyCmd) {
        throw "Python 3 is required to generate installer icons (or pass -CargoOnly)."
    }
    Write-Host "[AllUse Build] Generating installer icons in $IconsDir..." -ForegroundColor Cyan
    & $pyCmd.Source (Join-Path $ProjectRoot "scripts\generate-icons.py") --out-dir $IconsDir | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "generate-icons.py failed with exit code $LASTEXITCODE" }
    New-Item -ItemType Directory -Force -Path $DistWinDir | Out-Null
}

$VcVarsPath = $null
if ($Toolchain -eq "msvc") {
    $VcVarsPath = Find-VcVarsAll
    if (-not $VcVarsPath) {
        throw "MSVC vcvarsall.bat not found. Re-run with -Toolchain gnullvm or install Visual Studio Build Tools."
    }
}

foreach ($targetArch in $TargetArches) {
    $env:PATH = $OriginalPath
    $triple = Get-TargetTriple $targetArch $Toolchain
    $mingwTriple = Get-MingwTriple $targetArch
    $tripleKey = $triple -replace '-', '_'
    $tripleUpper = $tripleKey.ToUpperInvariant()

    Write-Host ""
    Write-Host "=== Building Windows $targetArch ($triple) ===" -ForegroundColor Yellow

    if (Get-Command rustup -ErrorAction SilentlyContinue) {
        rustup target add $triple
        if ($LASTEXITCODE -ne 0) { throw "rustup target add $triple failed" }
    }

    if ($Toolchain -eq "gnullvm") {
        $llvmRoot = $null
        foreach ($h in $CandidateHomes) {
            $cand = Join-Path $h ".llvm-mingw"
            if (Test-Path (Join-Path $cand "bin")) {
                $llvmRoot = $cand
                break
            }
        }
        if ($llvmRoot) {
            $llvmBin = Join-Path $llvmRoot "bin"
            $targetMingwBin = Join-Path $llvmRoot "$mingwTriple\bin"
            $env:PATH = "$targetMingwBin;$llvmBin;$OriginalPath"

            $ccExe = Join-Path $llvmBin "$mingwTriple-gcc.exe"
            $cxxExe = Join-Path $llvmBin "$mingwTriple-g++.exe"
            $arExe = Join-Path $llvmBin "llvm-ar.exe"
            $clangExe = Join-Path $llvmBin "$mingwTriple-clang.exe"
            if (Test-Path $ccExe) { Set-Item -Path "Env:CC_$tripleKey" -Value $ccExe }
            if (Test-Path $cxxExe) { Set-Item -Path "Env:CXX_$tripleKey" -Value $cxxExe }
            if (Test-Path $arExe) { Set-Item -Path "Env:AR_$tripleKey" -Value $arExe }
            if (Test-Path $clangExe) { Set-Item -Path "Env:CARGO_TARGET_${tripleUpper}_LINKER" -Value $clangExe }
        }
        cargo build --release --target $triple --bin alluse --bin alluse-setup
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $triple" }
    } else {
        $hostVc = if ($HostArch -eq "arm64") { "arm64" } else { "amd64" }
        $tgtVc = if ($targetArch -eq "arm64") { "arm64" } else { "amd64" }
        $vcArg = if ($hostVc -eq $tgtVc) { $tgtVc } else { "${hostVc}_${tgtVc}" }
        $wrapper = Join-Path $env:TEMP ("alluse-msvc-" + $targetArch + "-" + [guid]::NewGuid().ToString("n") + ".cmd")
        @(
            "@echo off",
            "call `"$VcVarsPath`" $vcArg",
            "if errorlevel 1 exit /b 1",
            "cargo build --release --target $triple --bin alluse --bin alluse-setup"
        ) | Set-Content -Path $wrapper -Encoding ASCII
        try {
            cmd.exe /c "`"$wrapper`""
            if ($LASTEXITCODE -ne 0) { throw "MSVC cargo build failed for $triple ($LASTEXITCODE)" }
        } finally {
            Remove-Item $wrapper -Force -ErrorAction SilentlyContinue
        }
    }

    $targetReleaseDir = Join-Path $ProjectRoot "target\$triple\release"
    $appExe = Join-Path $targetReleaseDir "alluse.exe"
    $setupExe = Join-Path $targetReleaseDir "alluse-setup.exe"
    if (-not (Test-Path $appExe)) { throw "Missing compiled binary: $appExe" }
    if (-not (Test-Path $setupExe)) { throw "Missing compiled installer stub: $setupExe" }

    $wv2Dll = Find-WebView2Loader $triple $targetArch $HostArch
    if (-not $wv2Dll) {
        throw "Matching $targetArch WebView2Loader.dll could not be located."
    }
    $wv2Target = Join-Path $targetReleaseDir "WebView2Loader.dll"
    if ((Resolve-Path $wv2Dll).Path -ne $wv2Target) {
        Copy-Item $wv2Dll $wv2Target -Force
    }

    $unwindDll = $null
    if ($Toolchain -eq "gnullvm") {
        $unwindDll = Find-LibUnwind $triple $mingwTriple $CandidateHomes $targetArch $HostArch
        if (-not $unwindDll) {
            throw "Missing libunwind.dll for gnullvm target $triple"
        }
        $unwindTarget = Join-Path $targetReleaseDir "libunwind.dll"
        if ((Resolve-Path $unwindDll).Path -ne $unwindTarget) {
            Copy-Item $unwindDll $unwindTarget -Force
        }
    }

    if ($CargoOnly) {
        Write-Host "[AllUse Build] -CargoOnly: built $appExe and $setupExe" -ForegroundColor Green
        continue
    }

    $installerName = "AllUse-Setup-$ResolvedVersion-win32-$targetArch.exe"
    $installerOut = Join-Path $DistWinDir $installerName
    $icoFile = Join-Path $IconsDir "alluse.ico"
    $licenseFile = Join-Path $ProjectRoot "LICENSE"
    if (-not (Test-Path $icoFile)) { throw "Missing generated icon: $icoFile" }
    if (-not (Test-Path $licenseFile)) { throw "Missing LICENSE file: $licenseFile" }

    $packArgs = @(
        (Join-Path $ProjectRoot "scripts\package-installer.mjs"),
        "--os", "windows",
        "--arch", $targetArch,
        "--version", $ResolvedVersion,
        "--stub", $setupExe,
        "--input", "${appExe}:alluse.exe",
        "--input", "${wv2Target}:WebView2Loader.dll",
        "--input", "${icoFile}:alluse.ico",
        "--input", "${licenseFile}:LICENSE"
    )
    if ($unwindDll -and (Test-Path $unwindDll)) {
        $unwindStaged = Join-Path $targetReleaseDir "libunwind.dll"
        $packArgs += @("--input", "${unwindStaged}:libunwind.dll")
    }
    $llvmLic = if ($Toolchain -eq "gnullvm") { Find-LlvmLicense $CandidateHomes } else { $null }
    if ($llvmLic) {
        $packArgs += @("--input", "${llvmLic}:LICENSE-LLVM.txt")
    }
    $packArgs += @("--out", $installerOut)

    & node @packArgs
    if ($LASTEXITCODE -ne 0) { throw "package-installer.mjs failed for $targetArch" }

    $verifiedByBinary = $false
    if ($targetArch -eq $HostArch -or $HostArch -eq "arm64") {
        try {
            & $installerOut --verify-payload
            if ($LASTEXITCODE -eq 0) { $verifiedByBinary = $true }
        } catch {}
    }
    if (-not $verifiedByBinary) {
        & node (Join-Path $ProjectRoot "scripts\package-installer.mjs") --verify $installerOut
        if ($LASTEXITCODE -ne 0) { throw "Payload verification failed for $installerOut" }
    }

    $BuiltInstallers[$targetArch] = $installerOut
}

$env:PATH = $OriginalPath

if (-not $CargoOnly -and $BuiltInstallers.Count -gt 0) {
    $defaultSrc = if ($BuiltInstallers.ContainsKey($HostArch)) {
        $BuiltInstallers[$HostArch]
    } elseif ($BuiltInstallers.ContainsKey("x64")) {
        $BuiltInstallers["x64"]
    } else {
        $BuiltInstallers[$TargetArches[0]]
    }
    $defaultCopy = Join-Path $DistWinDir "AllUse-Setup-$ResolvedVersion.exe"
    Copy-Item $defaultSrc $defaultCopy -Force
    Write-Host "[AllUse Build] Host default installer copy: $defaultCopy" -ForegroundColor Green

    & node (Join-Path $ProjectRoot "scripts\generate-release-manifest.mjs") --version $ResolvedVersion --dir $DistWinDir
    if ($LASTEXITCODE -ne 0) { throw "generate-release-manifest.mjs failed" }
    Write-Host "[AllUse Build] Windows distribution ready in $DistWinDir" -ForegroundColor Green
}
