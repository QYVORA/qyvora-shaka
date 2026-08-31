# shaka installer for Windows.
#
# Downloads the latest prebuilt binary for this architecture from the GitHub
# release, verifies its SHA-256 against the published checksums.txt, installs
# it under %LOCALAPPDATA%\Programs\shaka\bin with the shaka icon, adds that
# directory to your user PATH, and creates a Start Menu shortcut — so shaka
# shows up in your app list with its logo, not as a bare command. Falls back
# to `go build` when no release binary is available yet.
#
# Usage:
#   irm https://raw.githubusercontent.com/QYVORA/qyvora-shaka/master/install.ps1 | iex
#
# Options:
#   $env:SHAKA_VERSION    pinned release tag, e.g. v1.0.0 (default: latest)
#   $env:SHAKA_PREFIX     install directory (default: %LOCALAPPDATA%\Programs\shaka)
#   -FromSource           always build from the current checkout instead of downloading

param(
    [switch]$FromSource
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "QYVORA/qyvora-shaka"
$Bin = "shaka"
$Version = $env:SHAKA_VERSION
$Prefix = $env:SHAKA_PREFIX
if (-not $Prefix) {
    $Prefix = Join-Path $env:LOCALAPPDATA "Programs\shaka"
}
$Dest = Join-Path $Prefix "bin"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Green }
function Write-Err($msg) { Write-Host "[!] $msg" -ForegroundColor Red }
function Write-Result($msg) { Write-Host "    $msg" }

function Resolve-Latest {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "$Bin-installer" }
    return $rel.tag_name
}

function Get-PublishedChecksum([string]$Asset) {
    try {
        $manifest = (Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$Version/checksums.txt" -UseBasicParsing).Content
        foreach ($line in ($manifest -split "`r?`n")) {
            $parts = ($line.Trim() -split "\s+")
            if ($parts.Count -ge 2 -and $parts[1] -eq $Asset) { return $parts[0] }
        }
    } catch { }
    return ""
}

function Build-FromSource {
    Write-Step "building $Bin from source..."
    if (-not (Test-Path (Join-Path $PWD "go.mod"))) {
        $cmd = Get-Command git -ErrorAction SilentlyContinue
        if (-not $cmd) { Write-Err "git is required to fetch the source"; exit 1 }
        $tmp = Join-Path $env:TEMP "qyvora-shaka-src"
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
        Write-Step "cloning QYVORA/qyvora-shaka..."
        git clone --depth 1 "https://github.com/QYVORA/qyvora-shaka" $tmp | Out-Null
        Set-Location $tmp
    }
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) { Write-Err "go is required to build from source"; exit 1 }
    go build -trimpath -ldflags "-s -w" -o (Join-Path $Dest "$Bin.exe") ./cmd/shaka
    Write-Step "built $Bin from source"
    Install-Icon
}

function Install-Icon {
    $ico = Join-Path $Dest "$Bin.ico"
    if (-not (Test-Path $ico)) {
        try {
            Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$Version/$Bin.ico" -OutFile $ico -UseBasicParsing
        } catch {
            $candidates = @(
                (Join-Path $PWD "assets\shaka.ico"),
                (Join-Path $PWD "$Bin.ico")
            )
            foreach ($c in $candidates) {
                if (Test-Path $c) { Copy-Item $c $ico -Force; break }
            }
        }
    }
    if (Test-Path $ico) {
        Write-Step "installed icon to $ico"
    } else {
        Write-Step "no icon available; skipping"
    }
}

function Install-StartMenuShortcut {
    $ico = Join-Path $Dest "$Bin.ico"
    if (-not (Test-Path $ico)) { return }
    $startMenu = [Environment]::GetFolderPath("Programs")
    if (-not $startMenu) { return }
    $lnk = Join-Path $startMenu "$Bin.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath = Join-Path $Dest "$Bin.exe"
    $sc.WorkingDirectory = $Dest
    $sc.IconLocation = $ico
    $sc.Description = "AI-assisted vulnerability discovery and reconnaissance framework"
    $sc.Save()
    Write-Step "created Start Menu shortcut $lnk"
}

# --- Source build -----------------------------------------------------------
if ($FromSource) {
    Build-FromSource
}
else {
    if (-not $Version) {
        $Version = Resolve-Latest
    }

    # Windows ARM64 runs x64 binaries, so prefer the native architecture but
    # fall back to amd64 when the release does not ship the arm64 asset.
    $Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        "ARM64" { "arm64" }
        default { "amd64" }
    }
    $Asset = "$Bin-windows-$Arch.exe"
    $exe = Join-Path $Dest "$Bin.exe"

    function Receive-Bin([string]$a) {
        try {
            Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$Version/$a" -OutFile $exe -UseBasicParsing
            return $true
        } catch { return $false }
    }

    $downloaded = Receive-Bin $Asset
    if (-not $downloaded -and $Arch -eq "arm64") {
        Write-Step "no $Asset in $Version; falling back to windows-amd64"
        $Asset = "$Bin-windows-amd64.exe"
        $downloaded = Receive-Bin $Asset
    }

    if ($downloaded) {
        $want = Get-PublishedChecksum $Asset
        if ($want) {
            $got = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
            if ($got -ne $want.ToLower()) {
                Remove-Item $exe -Force
                Write-Err "checksum mismatch for $Asset; aborting."
                exit 1
            }
            Write-Step "SHA-256 verified: $Asset"
        }
        else {
            Write-Step "no checksums.txt published for $Version; skipping verification"
        }

        Write-Step "installed $(Join-Path $Dest "$Bin.exe") ($Version)"
        Install-Icon
    }
    else {
        # No prebuilt binary for this platform/version — build from source
        # (from the current checkout when present, otherwise clone the repo).
        Write-Step "no prebuilt binary for windows/$Arch at $Version; building from source..."
        Build-FromSource
    }
}

# --- Start Menu ------------------------------------------------------------
Install-StartMenuShortcut

# --- PATH ------------------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Dest*") {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $Dest } else { "$Dest;$userPath" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Step "added $Dest to your user PATH (open a new terminal)"
}
else {
    Write-Step "$Dest is already on your PATH"
}

Write-Result "run 'shaka --help' to get started."
