# ==============================================================================
# AllUse Universal Windows Installer (Windows 11/10 ARM64 & AMD64 x64)
#
# One-line install in PowerShell:
#   irm https://raw.githubusercontent.com/akitect45/cheapai-alluse/main/install.ps1 | iex
#
# Script invocation with flags:
#   .\install.ps1 [-FromSource] [-Verify] [-Uninstall] [-InstallDir <path>] [-Version <tag>]
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$FromSource,
    [switch]$Verify,
    [switch]$Uninstall,
    [switch]$Help,
    [string]$InstallDir = "",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

$GitHubRepo = if ($env:ALLUSE_GITHUB_REPO) { $env:ALLUSE_GITHUB_REPO } else { "akitect45/cheapai-alluse" }
if (-not $Version) {
    $Version = if ($env:ALLUSE_VERSION) { $env:ALLUSE_VERSION } else { "latest" }
}
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$AllUseRoot = if ($env:ALLUSE_HOME) { $env:ALLUSE_HOME } else { Join-Path $UserHome ".alluse" }
if (-not $InstallDir) {
    $InstallDir = if ($env:ALLUSE_INSTALL_DIR) { $env:ALLUSE_INSTALL_DIR } else { Join-Path $AllUseRoot "bin" }
}
if ($env:ALLUSE_FROM_SOURCE -eq "1") { $FromSource = $true }
if ($env:ALLUSE_VERIFY -eq "1") { $Verify = $true }
if ($env:ALLUSE_UNINSTALL -eq "1") { $Uninstall = $true }

function Write-Info([string]$Message) {
    Write-Host "[AllUse Installer] $Message" -ForegroundColor Cyan
}

function Write-Step([string]$Message) {
    Write-Host "[AllUse Installer] -> $Message" -ForegroundColor Gray
}

function Write-Warn([string]$Message) {
    Write-Host "[AllUse Installer] [WARN] $Message" -ForegroundColor Yellow
}

function Write-Err([string]$Message) {
    Write-Host "[AllUse Installer] [ERROR] $Message" -ForegroundColor Red
}

if ($Help) {
    Write-Host @"
AllUse Universal Windows Installer (win32-arm64 & win32-x64)

Usage:
  irm https://raw.githubusercontent.com/$GitHubRepo/main/install.ps1 | iex
  .\install.ps1 [-FromSource] [-Verify] [-Uninstall] [-InstallDir <path>] [-Version <tag>]

Parameters:
  -FromSource          Build native binary via Cargo from source instead of prebuilt release
  -Verify              Run 'alluse.exe --version' and 'alluse.exe --doctor' after install
  -Uninstall           Remove AllUse binary directory and clean User PATH
  -InstallDir <path>   Destination folder for alluse.exe & WebView2Loader.dll (default: ~/.alluse/bin)
  -Version <tag>       Release tag to install (default: latest)
  -Help                Show this help message
"@
    return
}

function Resolve-WindowsArch {
    $candidates = @()
    if ($env:PROCESSOR_ARCHITEW6432) { $candidates += $env:PROCESSOR_ARCHITEW6432 }
    if ($env:PROCESSOR_ARCHITECTURE) { $candidates += $env:PROCESSOR_ARCHITECTURE }
    try {
        $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        if ($osArch) { $candidates += $osArch }
    } catch {}

    foreach ($raw in $candidates) {
        $u = $raw.ToUpperInvariant()
        if ($u -like "*ARM64*" -or $u -like "*AARCH64*") {
            return @{
                Arch        = "arm64"
                PlatformKey = "win32-arm64"
                Label       = "Windows ARM64 (aarch64)"
                MingwTriple = "aarch64-w64-mingw32"
            }
        }
    }
    return @{
        Arch        = "x64"
        PlatformKey = "win32-x64"
        Label       = "Windows AMD64 (x86_64)"
        MingwTriple = "x86_64-w64-mingw32"
    }
}

function Test-ValidPeBinary([string]$FilePath, [long]$MinBytes = 40960) {
    if (-not (Test-Path $FilePath)) { return $false }
    try {
        $item = Get-Item $FilePath -ErrorAction Stop
        if ($item.Length -lt $MinBytes) { return $false }
        $fs = [System.IO.File]::OpenRead($FilePath)
        try {
            $b0 = $fs.ReadByte()
            $b1 = $fs.ReadByte()
            # 'M' (0x4D = 77), 'Z' (0x5A = 90)
            return ($b0 -eq 0x4D -and $b1 -eq 0x5A)
        } finally {
            $fs.Close()
        }
    } catch {
        return $false
    }
}

function Test-WebView2Runtime {
    $wv2Guid = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    $regPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$wv2Guid",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$wv2Guid",
        "HKCU:\Software\Microsoft\EdgeUpdate\Clients\$wv2Guid",
        "HKCU:\Software\WOW6432Node\Microsoft\EdgeUpdate\Clients\$wv2Guid"
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            try {
                $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
                if ($props -and $props.pv -and $props.pv -ne "0.0.0.0") {
                    Write-Step "Microsoft Edge WebView2 Evergreen Runtime detected (v$($props.pv))."
                    return $true
                }
            } catch {}
        }
    }
    Write-Warn "Microsoft Edge WebView2 Evergreen Runtime was not found in standard registry keys."
    Write-Warn "Windows 11 includes WebView2 by default; on Windows 10 you can install it via:"
    Write-Warn "  winget install --id Microsoft.EdgeWebView2Runtime"
    return $false
}

function Remove-FromUserPath([string]$DirToRemove) {
    $normRemove = $DirToRemove.TrimEnd('\')
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath) {
        $parts = $userPath -split ';' | Where-Object {
            $_.Trim() -ne "" -and $_.Trim().TrimEnd('\') -ine $normRemove
        }
        $newPath = ($parts -join ';')
        if ($newPath -ne $userPath) {
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            Write-Step "Removed $DirToRemove from User PATH."
        }
    }
    if ($env:PATH) {
        $sessParts = $env:PATH -split ';' | Where-Object {
            $_.Trim() -ne "" -and $_.Trim().TrimEnd('\') -ine $normRemove
        }
        $env:PATH = ($sessParts -join ';')
    }
}

function Add-ToUserPath([string]$DirToAdd) {
    $normAdd = $DirToAdd.TrimEnd('\')
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $alreadyInUser = $false
    if ($userPath) {
        foreach ($p in ($userPath -split ';')) {
            if ($p.Trim().TrimEnd('\') -ieq $normAdd) {
                $alreadyInUser = $true
                break
            }
        }
    }
    if (-not $alreadyInUser) {
        $updatedUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $DirToAdd } else { "$userPath;$DirToAdd" }
        [Environment]::SetEnvironmentVariable("Path", $updatedUserPath, "User")
        Write-Step "Added $DirToAdd to User PATH."
    } else {
        Write-Step "$DirToAdd is already present in User PATH."
    }

    $alreadyInSession = $false
    if ($env:PATH) {
        foreach ($p in ($env:PATH -split ';')) {
            if ($p.Trim().TrimEnd('\') -ieq $normAdd) {
                $alreadyInSession = $true
                break
            }
        }
    }
    if (-not $alreadyInSession) {
        $env:PATH = "$DirToAdd;$env:PATH"
    }
}

function Invoke-Uninstall {
    Write-Info "Uninstalling AllUse from $InstallDir..."
    Get-Process -Name "alluse" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 150
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Step "Removed directory: $InstallDir"
    }
    Remove-FromUserPath $InstallDir
    Write-Info "AllUse has been uninstalled."
}

if ($Uninstall) {
    Invoke-Uninstall
    return
}

function Invoke-DownloadFile([string]$Url, [string]$DestPath) {
    $tmpPath = "$DestPath.part"
    if (Test-Path $tmpPath) { Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {}
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmpPath -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        if (Test-Path $tmpPath) {
            Move-Item -Path $tmpPath -Destination $DestPath -Force
            return $true
        }
    } catch {
        if (Test-Path $tmpPath) { Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue }
    }
    return $false
}

function Try-InstallPrebuilt([hashtable]$ArchInfo, [string]$TargetDir) {
    $arch = $ArchInfo.Arch
    $platformKey = $ArchInfo.PlatformKey
    $releaseBase = if ($Version -eq "latest") {
        "https://github.com/$GitHubRepo/releases/latest/download"
    } else {
        "https://github.com/$GitHubRepo/releases/download/$Version"
    }

    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }

    $exeDest = Join-Path $TargetDir "alluse.exe"
    $dllDest = Join-Path $TargetDir "WebView2Loader.dll"

    # 1. Try downloading bundle zip: alluse-win32-<arch>.zip
    $zipAsset = "alluse-$platformKey.zip"
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) "alluse-$platformKey-$PID.zip"
    $tmpExtract = Join-Path ([System.IO.Path]::GetTempPath()) "alluse-extract-$PID"

    Write-Step "Checking prebuilt release archive ($zipAsset) from github.com/$GitHubRepo..."
    if (Invoke-DownloadFile "$releaseBase/$zipAsset" $tmpZip) {
        try {
            if (Test-Path $tmpExtract) { Remove-Item $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue }
            Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
            $foundExe = Get-ChildItem -Path $tmpExtract -Recurse -Filter "alluse*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
            $foundDll = Get-ChildItem -Path $tmpExtract -Recurse -Filter "WebView2Loader*.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundExe -and (Test-ValidPeBinary $foundExe.FullName 1048576)) {
                Copy-Item $foundExe.FullName $exeDest -Force
                if ($foundDll -and (Test-ValidPeBinary $foundDll.FullName 40960)) {
                    Copy-Item $foundDll.FullName $dllDest -Force
                }
                $foundUnwind = Get-ChildItem -Path $tmpExtract -Recurse -Filter "libunwind.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($foundUnwind) {
                    Copy-Item $foundUnwind.FullName (Join-Path $TargetDir "libunwind.dll") -Force
                }
                if (-not (Test-ValidPeBinary $dllDest 40960)) {
                    [void](Invoke-DownloadFile "$releaseBase/WebView2Loader-$arch.dll" $dllDest)
                }
                if (Test-ValidPeBinary $dllDest 40960) {
                    Write-Step "Installed prebuilt release archive ($zipAsset)."
                    return $true
                }
            }
        } catch {
            # Fall through to direct asset download
        } finally {
            if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue }
            if (Test-Path $tmpExtract) { Remove-Item $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # 2. Try downloading individual assets: alluse-win32-<arch>.exe + WebView2Loader-<arch>.dll
    $exeAsset = "alluse-$platformKey.exe"
    $dllAsset = "WebView2Loader-$arch.dll"
    Write-Step "Checking direct prebuilt assets ($exeAsset + $dllAsset)..."
    $exeOk = Invoke-DownloadFile "$releaseBase/$exeAsset" $exeDest
    if ($exeOk -and (Test-ValidPeBinary $exeDest 1048576)) {
        $dllOk = Invoke-DownloadFile "$releaseBase/$dllAsset" $dllDest
        if ($dllOk -and (Test-ValidPeBinary $dllDest 40960)) {
            Write-Step "Downloaded verified prebuilt $exeAsset and $dllAsset."
            return $true
        }
    }

    return $false
}

function Ensure-CargoToolchainEnv([hashtable]$ArchInfo) {
    $userProfileDirs = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName ".cargo\bin\cargo.exe") } | Select-Object -ExpandProperty FullName)
    $candidateHomes = @($UserHome, $HOME, (if ($env:USERNAME) { "C:\Users\$($env:USERNAME)" } else { $null })) + $userProfileDirs | Where-Object { $_ } | Select-Object -Unique
    foreach ($hDir in $candidateHomes) {
        $cDir = Join-Path $hDir ".cargo"
        $rDir = Join-Path $hDir ".rustup"
        if ((Test-Path (Join-Path $cDir "bin\cargo.exe")) -and (-not $env:CARGO_HOME)) { $env:CARGO_HOME = $cDir }
        if ((Test-Path (Join-Path $rDir "settings.toml")) -and (-not $env:RUSTUP_HOME)) { $env:RUSTUP_HOME = $rDir }
        $cargoBin = Join-Path $hDir ".cargo\bin"
        $mingwBin = Join-Path $hDir ".llvm-mingw\bin"
        $mingwTripleBin = Join-Path $hDir ".llvm-mingw\$($ArchInfo.MingwTriple)\bin"
        foreach ($dir in @($cargoBin, $mingwBin, $mingwTripleBin)) {
            if ((Test-Path $dir) -and ($env:PATH -notlike "*$dir*")) {
                $env:PATH = "$dir;$env:PATH"
            }
        }
    }
}

function Install-FromSource([hashtable]$ArchInfo, [string]$TargetDir) {
    Write-Step "Preparing Cargo source build for $($ArchInfo.Label)..."
    Ensure-CargoToolchainEnv $ArchInfo

    if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
        Write-Err "Rust toolchain ('cargo') was not found in PATH."
        Write-Info "Install Rust on Windows via:"
        Write-Host "  winget install --id Rustlang.Rustup" -ForegroundColor White
        throw "Missing cargo toolchain."
    }

    $srcRepoDir = $null
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if ((Test-Path (Join-Path $scriptDir "Cargo.toml")) -and (Test-Path (Join-Path $scriptDir "src\main.rs"))) {
        $srcRepoDir = $scriptDir
        Write-Step "Using local AllUse repository checkout at $srcRepoDir"
    } elseif ((Test-Path ".\Cargo.toml") -and (Test-Path ".\src\main.rs")) {
        $srcRepoDir = (Get-Location).Path
        Write-Step "Using current directory repository checkout at $srcRepoDir"
    } else {
        if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
            throw "'git' is required to clone https://github.com/$GitHubRepo.git for source build."
        }
        $srcRepoDir = Join-Path $AllUseRoot "src"
        if (-not (Test-Path $AllUseRoot)) {
            New-Item -ItemType Directory -Path $AllUseRoot -Force | Out-Null
        }
        if (Test-Path (Join-Path $srcRepoDir ".git")) {
            Write-Step "Updating existing source checkout in $srcRepoDir..."
            Push-Location $srcRepoDir
            try {
                git fetch --depth 1 origin | Out-Null
                git reset --hard origin/main | Out-Null
            } catch {} finally {
                Pop-Location
            }
        } else {
            if (Test-Path $srcRepoDir) { Remove-Item $srcRepoDir -Recurse -Force -ErrorAction SilentlyContinue }
            Write-Step "Cloning https://github.com/$GitHubRepo.git into $srcRepoDir..."
            if ($Version -ne "latest") {
                git clone --depth 1 --branch $Version "https://github.com/$GitHubRepo.git" $srcRepoDir
            } else {
                git clone --depth 1 "https://github.com/$GitHubRepo.git" $srcRepoDir
            }
        }
    }

    Write-Step "Running 'cargo build --release'..."
    Push-Location $srcRepoDir
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release exited with code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    $builtExe = Join-Path $srcRepoDir "target\release\alluse.exe"
    if (-not (Test-ValidPeBinary $builtExe 1048576)) {
        throw "Compiled binary at $builtExe is missing or invalid."
    }

    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $exeDest = Join-Path $TargetDir "alluse.exe"
    $dllDest = Join-Path $TargetDir "WebView2Loader.dll"
    Copy-Item $builtExe $exeDest -Force

    # Locate WebView2Loader.dll for the target architecture
    $arch = $ArchInfo.Arch
    $wv2Candidates = @(
        (Join-Path $srcRepoDir "target\release\WebView2Loader.dll"),
        (Join-Path $srcRepoDir "data\backups\dlls\WebView2Loader.dll"),
        (Join-Path $srcRepoDir "windows-webview2-src\$arch\WebView2Loader.dll")
    )
    $foundWv2 = $wv2Candidates | Where-Object { Test-ValidPeBinary $_ 40960 } | Select-Object -First 1
    if (-not $foundWv2) {
        $buildOutMatch = Get-ChildItem -Path (Join-Path $srcRepoDir "target") -Recurse -Filter "WebView2Loader.dll" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\$arch\WebView2Loader.dll" } |
            Select-Object -First 1
        if ($buildOutMatch -and (Test-ValidPeBinary $buildOutMatch.FullName 40960)) {
            $foundWv2 = $buildOutMatch.FullName
        }
    }
    if ($foundWv2) {
        Copy-Item $foundWv2 $dllDest -Force
    } else {
        $releaseBase = "https://github.com/$GitHubRepo/releases/latest/download"
        [void](Invoke-DownloadFile "$releaseBase/WebView2Loader-$arch.dll" $dllDest)
    }

    # Copy libunwind.dll if present
    $unwindCandidates = @(
        (Join-Path $srcRepoDir "target\release\libunwind.dll"),
        (Join-Path $srcRepoDir "data\backups\dlls\libunwind.dll"),
        (Join-Path $UserHome ".llvm-mingw\$($ArchInfo.MingwTriple)\bin\libunwind.dll")
    )
    $foundUnwind = $unwindCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($foundUnwind) {
        Copy-Item $foundUnwind (Join-Path $TargetDir "libunwind.dll") -Force
    }
}

function Ensure-CmdShim([string]$TargetDir) {
    $cmdPath = Join-Path $TargetDir "alluse.cmd"
    $shimContent = "@echo off`r`n`"%~dp0alluse.exe`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    Set-Content -Path $cmdPath -Value $shimContent -Encoding ASCII -Force
}

$ArchInfo = Resolve-WindowsArch
Write-Info "Target Platform : $($ArchInfo.Label) ($($ArchInfo.PlatformKey))"
Write-Info "Install Dir     : $InstallDir"

[void](Test-WebView2Runtime)

if ($InstallDir -ieq (Join-Path $UserHome ".alluse\bin")) {
    Get-Process -Name "alluse" -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and ($_.Path -ieq (Join-Path $InstallDir "alluse.exe")) } catch { $false }
    } | Stop-Process -Force -ErrorAction SilentlyContinue
}

if ($FromSource) {
    Install-FromSource -ArchInfo $ArchInfo -TargetDir $InstallDir
} else {
    $prebuiltOk = Try-InstallPrebuilt -ArchInfo $ArchInfo -TargetDir $InstallDir
    if (-not $prebuiltOk) {
        Write-Warn "Prebuilt release binary not available for $($ArchInfo.PlatformKey) ($Version); falling back to Cargo source build..."
        Install-FromSource -ArchInfo $ArchInfo -TargetDir $InstallDir
    }
}

Ensure-CmdShim $InstallDir
Add-ToUserPath $InstallDir

$InstalledExe = Join-Path $InstallDir "alluse.exe"
if ($Verify) {
    Write-Step "Running verification (--version & --doctor)..."
    & $InstalledExe --version
    & $InstalledExe --doctor
}

Write-Info "AllUse installation complete! Run 'alluse' to launch the native workbench."
