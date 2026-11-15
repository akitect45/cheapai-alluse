param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PassThruArgs
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$GitHubRepo  = if ($env:ALLUSE_GITHUB_REPO) { $env:ALLUSE_GITHUB_REPO } else { "akitect45/cheapai-alluse" }

$IsWinHost = ($env:OS -eq "Windows_NT") -or ($IsWindows -eq $true)
if (-not $IsWinHost) {
    $PosixLauncher = Join-Path $ProjectRoot "alluse"
    if (Test-Path $PosixLauncher) {
        & sh $PosixLauncher @PassThruArgs
        exit $LASTEXITCODE
    }
}

$ArchCandidates = @()
if ($env:PROCESSOR_ARCHITEW6432) { $ArchCandidates += $env:PROCESSOR_ARCHITEW6432 }
if ($env:PROCESSOR_ARCHITECTURE) { $ArchCandidates += $env:PROCESSOR_ARCHITECTURE }
try {
    $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($osArch) { $ArchCandidates += $osArch }
} catch {}

$Wv2ArchDir = "x64"
foreach ($cand in $ArchCandidates) {
    $u = $cand.ToUpperInvariant()
    if ($u -like "*ARM64*" -or $u -like "*AARCH64*") {
        $Wv2ArchDir = "arm64"
        break
    }
}
$MingwTriple = if ($Wv2ArchDir -eq "arm64") { "aarch64-w64-mingw32" } else { "x86_64-w64-mingw32" }
$ArchLabel   = if ($Wv2ArchDir -eq "arm64") { "ARM64 (aarch64)" } else { "AMD64 (x86_64)" }

# Discover local Rust / LLVM-MinGW toolchains across standard and profile home dirs
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$UserProfileDirs = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName ".cargo\bin\cargo.exe") } | Select-Object -ExpandProperty FullName)
$CandidateHomes = @($UserHome, $HOME, (if ($env:USERNAME) { "C:\Users\$($env:USERNAME)" } else { $null })) + $UserProfileDirs | Where-Object { $_ } | Select-Object -Unique
foreach ($hDir in $CandidateHomes) {
    $cDir = Join-Path $hDir ".cargo"
    $rDir = Join-Path $hDir ".rustup"
    if ((Test-Path (Join-Path $cDir "bin\cargo.exe")) -and (-not $env:CARGO_HOME)) { $env:CARGO_HOME = $cDir }
    if ((Test-Path (Join-Path $rDir "settings.toml")) -and (-not $env:RUSTUP_HOME)) { $env:RUSTUP_HOME = $rDir }
    foreach ($toolDir in @(
        (Join-Path $hDir ".cargo\bin"),
        (Join-Path $hDir ".llvm-mingw\bin"),
        (Join-Path $hDir ".llvm-mingw\$MingwTriple\bin")
    )) {
        if ((Test-Path $toolDir) -and ($env:PATH -notlike "*$toolDir*")) {
            $env:PATH = "$toolDir;$env:PATH"
        }
    }
}

$ReleaseDir = Join-Path $ProjectRoot "target\release"
$DebugDir   = Join-Path $ProjectRoot "target\debug"
$ReleaseExe = Join-Path $ReleaseDir "alluse.exe"
$DebugExe   = Join-Path $DebugDir "alluse.exe"
$GoldenExe  = Join-Path $ProjectRoot "data\backups\alluse_golden.exe"
$DllBakDir  = Join-Path $ProjectRoot "data\backups\dlls"

# Keep project root clean of legacy Windows-specific .exe/.dll artifacts
foreach ($legacyFile in @("alluse.exe", "alluse.exe.old", "WebView2Loader.dll", "libunwind.dll")) {
    $legacyPath = Join-Path $ProjectRoot $legacyFile
    if (Test-Path $legacyPath) {
        Remove-Item $legacyPath -Force -ErrorAction SilentlyContinue
    }
}

$ReadOnlyFlags = @("--version", "-V", "--help", "-h", "--doctor", "--verify", "--heal", "--run-asl")
$IsReadOnlyCli = $false
if ($PassThruArgs -and $PassThruArgs.Count -gt 0) {
    foreach ($argItem in $PassThruArgs) {
        if ($ReadOnlyFlags -contains $argItem) {
            $IsReadOnlyCli = $true
            break
        }
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
            return ($b0 -eq 0x4D -and $b1 -eq 0x5A)
        } finally {
            $fs.Close()
        }
    } catch {
        return $false
    }
}

function Invoke-SafeDownload([string]$Url, [string]$DestPath) {
    $tmpPath = "$DestPath.part"
    if (Test-Path $tmpPath) { Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {}
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmpPath -UseBasicParsing -TimeoutSec 25 -ErrorAction Stop
        if (Test-Path $tmpPath) {
            Move-Item -Path $tmpPath -Destination $DestPath -Force
            return $true
        }
    } catch {
        if (Test-Path $tmpPath) { Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue }
    }
    return $false
}

function Ensure-RuntimeDlls([string]$TargetDir) {
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $wv2Target = Join-Path $TargetDir "WebView2Loader.dll"
    if (-not (Test-ValidPeBinary $wv2Target 40960)) {
        $localCandidates = @(
            (Join-Path $DllBakDir "WebView2Loader.dll"),
            (Join-Path $ProjectRoot "windows-webview2-src\$Wv2ArchDir\WebView2Loader.dll")
        )
        $foundLocal = $localCandidates | Where-Object { Test-ValidPeBinary $_ 40960 } | Select-Object -First 1
        if (-not $foundLocal -and (Test-Path (Join-Path $ProjectRoot "target"))) {
            $wv2Src = Get-ChildItem -Path (Join-Path $ProjectRoot "target") -Recurse -Filter "WebView2Loader.dll" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -like "*\$Wv2ArchDir\WebView2Loader.dll" -and (Test-ValidPeBinary $_.FullName 40960) } |
                Select-Object -First 1
            if ($wv2Src) {
                $foundLocal = $wv2Src.FullName
            }
        }
        if ($foundLocal) {
            Copy-Item $foundLocal $wv2Target -Force
        } else {
            $dllUrl = "https://github.com/$GitHubRepo/releases/latest/download/WebView2Loader-$Wv2ArchDir.dll"
            [void](Invoke-SafeDownload $dllUrl $wv2Target)
        }
    }

    $unwindTarget = Join-Path $TargetDir "libunwind.dll"
    if (-not (Test-Path $unwindTarget)) {
        $bakUnwind = Join-Path $DllBakDir "libunwind.dll"
        $unwindSrc = Join-Path $UserHome ".llvm-mingw\$MingwTriple\bin\libunwind.dll"
        if (Test-Path $bakUnwind) {
            Copy-Item $bakUnwind $unwindTarget -Force
        } elseif (Test-Path $unwindSrc) {
            Copy-Item $unwindSrc $unwindTarget -Force
        }
    }
}

function Try-DownloadPrebuiltWindowsBinary {
    if (-not (Test-Path $ReleaseDir)) {
        New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null
    }
    $exeAsset = "alluse-win32-$Wv2ArchDir.exe"
    $dllAsset = "WebView2Loader-$Wv2ArchDir.dll"
    $baseUrl  = "https://github.com/$GitHubRepo/releases/latest/download"

    Write-Host "[AllUse] Attempting to download prebuilt $exeAsset from github.com/$GitHubRepo..." -ForegroundColor Cyan
    $exeOk = Invoke-SafeDownload "$baseUrl/$exeAsset" $ReleaseExe
    if ($exeOk -and (Test-ValidPeBinary $ReleaseExe 1048576)) {
        $wv2Target = Join-Path $ReleaseDir "WebView2Loader.dll"
        if (-not (Test-ValidPeBinary $wv2Target 40960)) {
            [void](Invoke-SafeDownload "$baseUrl/$dllAsset" $wv2Target)
        }
        Ensure-RuntimeDlls $ReleaseDir
        return $true
    }
    if (Test-Path $ReleaseExe) {
        Remove-Item $ReleaseExe -Force -ErrorAction SilentlyContinue
    }
    return $false
}

function Test-SourceNewerThanBinary([string]$BinPath) {
    if (-not (Test-ValidPeBinary $BinPath 1048576)) { return $true }
    try {
        $binTime = (Get-Item $BinPath -ErrorAction Stop).LastWriteTimeUtc
        foreach ($metaFile in @("Cargo.toml", "build.rs")) {
            $mp = Join-Path $ProjectRoot $metaFile
            if ((Test-Path $mp) -and ((Get-Item $mp).LastWriteTimeUtc -gt $binTime)) {
                return $true
            }
        }
        $srcDir = Join-Path $ProjectRoot "src"
        if (Test-Path $srcDir) {
            $newerSrc = Get-ChildItem -Path $srcDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTimeUtc -gt $binTime } |
                Select-Object -First 1
            if ($newerSrc) { return $true }
        }
    } catch {}
    return $false
}

function Invoke-BootstrapperSelfRecovery {
    Write-Host "[AllUse Self-Recovery] Diagnosing and restoring binary & runtime environment ($ArchLabel)..." -ForegroundColor Yellow
    if (-not (Test-Path $ReleaseDir)) {
        New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null
    }
    Ensure-RuntimeDlls $ReleaseDir
    $hasCargo = [bool](Get-Command "cargo" -ErrorAction SilentlyContinue)

    if ((Test-ValidPeBinary $GoldenExe 1048576) -and (-not $hasCargo)) {
        Write-Host "[AllUse Self-Recovery] Restoring verified golden binary from data\backups\alluse_golden.exe..." -ForegroundColor Cyan
        Copy-Item $GoldenExe $ReleaseExe -Force -ErrorAction SilentlyContinue
        Ensure-RuntimeDlls $ReleaseDir
        return
    }

    if ($hasCargo) {
        Write-Host "[AllUse Self-Recovery] Rebuilding native $ArchLabel binary from source..." -ForegroundColor Cyan
        Push-Location $ProjectRoot
        try {
            cargo build --release
        } finally {
            Pop-Location
        }
        Ensure-RuntimeDlls $ReleaseDir
        if (Test-ValidPeBinary $ReleaseExe 1048576) {
            return
        }
    }

    if (Try-DownloadPrebuiltWindowsBinary) {
        return
    }

    if (Test-ValidPeBinary $GoldenExe 1048576) {
        Write-Host "[AllUse Self-Recovery] Restoring verified golden binary from data\backups\alluse_golden.exe..." -ForegroundColor Cyan
        Copy-Item $GoldenExe $ReleaseExe -Force -ErrorAction SilentlyContinue
        Ensure-RuntimeDlls $ReleaseDir
    }
}

# Read-Only CLI Fast Path (--version, -V, --help, -h, --doctor, --verify, --heal, --run-asl):
# Do NOT kill existing running alluse GUI processes!
if ($IsReadOnlyCli) {
    $hasCargo = [bool](Get-Command "cargo" -ErrorAction SilentlyContinue)
    $runningProcs = @(Get-Process -Name "alluse" -ErrorAction SilentlyContinue)

    if (-not (Test-ValidPeBinary $ReleaseExe 1048576)) {
        if (-not $hasCargo) {
            [void](Try-DownloadPrebuiltWindowsBinary)
        }
        if (-not (Test-ValidPeBinary $ReleaseExe 1048576)) {
            Invoke-BootstrapperSelfRecovery
        }
    } elseif ($hasCargo -and ($runningProcs.Count -eq 0) -and (Test-SourceNewerThanBinary $ReleaseExe)) {
        Write-Host "[AllUse] Source changes detected — rebuilding release binary..." -ForegroundColor Cyan
        Push-Location $ProjectRoot
        try {
            cargo build --release
        } finally {
            Pop-Location
        }
    }

    Ensure-RuntimeDlls $ReleaseDir
    $FilteredArgs = @($PassThruArgs | Where-Object { $_ -ne "--wait" })
    & $ReleaseExe @FilteredArgs
    exit $LASTEXITCODE
}

# Non-Read-Only Mode (GUI Launch or Server/Daemon CLI flags):
$hasCargo = [bool](Get-Command "cargo" -ErrorAction SilentlyContinue)
$ExeToRun = $null

if (Test-ValidPeBinary $ReleaseExe 1048576) {
    if ($hasCargo -and (Test-SourceNewerThanBinary $ReleaseExe)) {
        if (-not $PassThruArgs -or $PassThruArgs.Count -eq 0) {
            Get-Process -Name "alluse" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 150
        }
        Write-Host "[AllUse] Source files updated — rebuilding native $ArchLabel binary..." -ForegroundColor Cyan
        Push-Location $ProjectRoot
        try {
            cargo build --release
        } finally {
            Pop-Location
        }
    }
    Ensure-RuntimeDlls $ReleaseDir
    $ExeToRun = $ReleaseExe
} elseif (-not $hasCargo -and (Try-DownloadPrebuiltWindowsBinary)) {
    $ExeToRun = $ReleaseExe
} elseif (Test-ValidPeBinary $GoldenExe 1048576 -and (-not $hasCargo)) {
    Invoke-BootstrapperSelfRecovery
    $ExeToRun = $ReleaseExe
} elseif (Test-ValidPeBinary $DebugExe 1048576 -and (-not $hasCargo)) {
    Ensure-RuntimeDlls $DebugDir
    $ExeToRun = $DebugExe
} else {
    Invoke-BootstrapperSelfRecovery
    $ExeToRun = $ReleaseExe
}

# Non-Read-Only CLI mode (--web, --server, --headless, --auto-verify-gui, --opencode-demo, --wait)
if ($PassThruArgs -and $PassThruArgs.Count -gt 0) {
    if ($PassThruArgs -contains "--wait") {
        $Filtered = @($PassThruArgs | Where-Object { $_ -ne "--wait" })
        & $ExeToRun @Filtered
        exit $LASTEXITCODE
    }
    & $ExeToRun @PassThruArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[AllUse] Process exited with code $LASTEXITCODE — attempting automatic self-recovery..." -ForegroundColor Yellow
        Invoke-BootstrapperSelfRecovery
        $ExeToRun = $ReleaseExe
        & $ExeToRun @PassThruArgs
        exit $LASTEXITCODE
    }
    exit 0
}

# Interactive GUI Launch Mode (no arguments):
Get-Process -Name "alluse" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 150

Write-Host "[AllUse] Starting Native Windows ($ArchLabel) Assistant..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $ExeToRun -WorkingDirectory $ProjectRoot -WindowStyle Normal -PassThru

$ready = $false
$stateData = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 150
    if ($proc.HasExited) {
        Write-Host ("[AllUse] Process exited early (0x{0:X8}) — triggering Self-Recovery..." -f $proc.ExitCode) -ForegroundColor Yellow
        Invoke-BootstrapperSelfRecovery
        $proc = Start-Process -FilePath $ReleaseExe -WorkingDirectory $ProjectRoot -WindowStyle Normal -PassThru
        Start-Sleep -Milliseconds 600
    }
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8877/api/status" -TimeoutSec 1 -ErrorAction Stop
        if ($resp.ok) {
            $ready = $true
            $stateData = $resp
            break
        }
    } catch {
        # Wait for HTTP server + WebView2 initialization
    }
}

if ($ready) {
    $monCount = if ($stateData.monitors -and $stateData.monitors.monitors) { $stateData.monitors.monitors.Count } else { 1 }
    $primaryMon = if ($monCount -gt 0) { $stateData.monitors.monitors[0].device + " (" + $stateData.monitors.monitors[0].width + "x" + $stateData.monitors.monitors[0].height + " @ " + $stateData.monitors.monitors[0].scale_percent + "%)" } else { "Default" }
    $modelStr = $stateData.config.provider_name + "/" + $stateData.config.model + " (" + $stateData.config.effort + ")"
    $toolCount = if ($stateData.custom_tools) { $stateData.custom_tools.Count } else { 0 }
    $widgetCount = if ($stateData.ui_widgets) { $stateData.ui_widgets.Count } else { 0 }
    Write-Host "[AllUse] Native $ArchLabel Workbench is LIVE and focused!" -ForegroundColor Green
    Write-Host ("  - PID        : {0} ({1})" -f $proc.Id, $ArchLabel) -ForegroundColor Gray
    Write-Host ("  - Endpoint   : http://127.0.0.1:8877") -ForegroundColor Gray
    Write-Host ("  - Display    : {0}" -f $primaryMon) -ForegroundColor Gray
    Write-Host ("  - Model      : {0}" -f $modelStr) -ForegroundColor Gray
    Write-Host ("  - Self-Heal  : Active (Guardian + Golden Snapshot + {0} Custom Tools / {1} UI Widgets)" -f $toolCount, $widgetCount) -ForegroundColor Gray
    Write-Host ("  - Stop Key   : Physical [ESC] key interrupts Computer Use at any time") -ForegroundColor DarkYellow
} else {
    Write-Host ("[AllUse] Started PID {0} (initializing WebView2...)" -f $proc.Id) -ForegroundColor Yellow
}
