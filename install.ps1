#!/usr/bin/env pwsh
#
# SHAKA CLI — QYVORA installer for Windows
#
# This file is GENERATED from qyvora-dist/installer.ps1.template.
# Do not edit it by hand: change the template + qyvora-dist/tools.def, then run
#   qyvora-dist/generate.sh
#
# Windows-specific behaviour worth knowing:
#   * PATH is managed with [Environment]::SetEnvironmentVariable using the
#     User scope. No Unix shell syntax is ever written to a Windows config.
#   * Architecture is read from the OS itself (PROCESSOR_ARCHITECTURE and the
#     real PROCESSOR_ARCHITEW6432 override for x64 emulation on ARM64), not
#     from `uname`, which does not exist here.
#   * Artifacts are verified by SHA-256, then executed before and after the
#     install; a binary that will not start is never left on disk.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $Prefix = '',
    [string] $Version = '',
    [switch] $Uninstall,
    [switch] $FromSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# === TOOL METADATA — generated from qyvora-dist/tools.def ===
$Tool       = 'shaka'
$ToolTitle  = 'SHAKA'
$Repo       = 'QYVORA/qyvora-shaka'
$MainPkg    = './cmd/shaka'
$Android    = 'prebuilt'
$SourceBuild = '1'
$MinGo      = '1.26'
$IconAsset  = 'shaka.png'
$IcoAsset   = 'shaka.ico'
$AppComment = 'Active Directory and identity attack analysis'
# === end metadata ===

$InstallerVersion = '2'
$ExitOk = 0; $ExitFatal = 1; $ExitUnsupported = 2; $ExitVerify = 3

function Write-Ok    { param([string]$m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Info  { param([string]$m) Write-Host "  [..] $m" -ForegroundColor Cyan }
function Write-Warn  { param([string]$m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Err   { param([string]$m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Note  { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor DarkGray }

function Stop-With {
    param([int]$Code, [string]$Message)
    Write-Err $Message
    exit $Code
}

function Get-ToolTarget {
    # Real OS architecture, not the emulated one. PROCESSOR_ARCHITEW6432 is
    # what a 32-bit or x64 process sees when it runs under ARM64 emulation.
    $native = $env:PROCESSOR_ARCHITEW6432
    if (-not $native) { $native = $env:PROCESSOR_ARCHITECTURE }
    switch ("$native") {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        'x86'   { return 'i386' }
        default { return 'unsupported' }
    }
}

function Get-InstallDir {
    if ($Prefix) { return $Prefix }
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    return (Join-Path $local 'QYVORA\bin')
}

function Test-OnUserPath {
    param([string]$Dir)
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { return $false }
    return (($userPath -split ';') | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') }).Count -gt 0
}

function Add-ToUserPath {
    param([string]$Dir)
    if (Test-OnUserPath $Dir) {
        Write-Ok "Install directory is already on your user PATH: $Dir"
        return
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $new = if ([string]::IsNullOrEmpty($userPath)) { $Dir } else { $userPath.TrimEnd(';') + ';' + $Dir }
    [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    Write-Ok "Added $Dir to your user PATH."
    Write-Note "Open a new terminal for the change to take effect."
}

function Get-ArtifactName {
    param([string]$Arch)
    $name = "$Tool-windows-$Arch"
    if ($Arch -eq 'amd64' -or $Arch -eq 'arm64') { $name += '.exe' }
    return $name
}

function Invoke-Download {
    param([string]$Uri, [string]$OutFile)
    if (-not $Uri.StartsWith('https://')) {
        Write-Err "Refusing to download from a non-HTTPS origin: $Uri"
        return $false
    }
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -MaximumRedirection 5
        return $true
    } catch {
        Write-Err "Download failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-Checksum {
    param([string]$File, [string]$Artifact, [string]$ChecksumsPath)
    $want = $null
    foreach ($line in Get-Content -LiteralPath $ChecksumsPath) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2) {
            $name = $parts[1].Trim().TrimStart('*')
            if ($name -eq $Artifact) { $want = $parts[0]; break }
        }
    }
    if (-not $want) {
        Write-Err "No checksum entry for $Artifact in checksums.txt."
        return $false
    }
    $got = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($want.ToLowerInvariant() -ne $got) {
        Write-Err "SHA-256 mismatch for ${Artifact}: expected $want, got $got."
        return $false
    }
    Write-Ok "SHA-256 verified ($got)"
    return $true
}

function Test-Executable {
    param([string]$Path, [string]$Arch)
    # PE signature + machine word behind e_lfanew.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64) { Write-Err 'Artifact is truncated.'; return $false }
    if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        Write-Err 'Artifact is not a Windows PE executable (missing MZ signature).'
        return $false
    }
    $lfanew = [BitConverter]::ToInt32($bytes, 60)
    if ($lfanew -lt 0 -or ($lfanew + 6) -gt $bytes.Length) {
        Write-Err 'PE header offset is unreadable.'
        return $false
    }
    if ($bytes[$lfanew] -ne 0x50 -or $bytes[$lfanew + 1] -ne 0x45 -or
        $bytes[$lfanew + 2] -ne 0 -or $bytes[$lfanew + 3] -ne 0) {
        Write-Err 'Artifact is not a Windows PE executable (missing PE signature).'
        return $false
    }
    $machine = [BitConverter]::ToUInt16($bytes, $lfanew + 4)
    $want = @{ amd64 = 34404; arm64 = 43620 }[$Arch]
    if ($want -and $machine -ne $want) {
        Write-Err "PE machine mismatch: artifact=$machine, target needs $want."
        return $false
    }
    Write-Ok "PE, machine=$machine"
    return $true
}

function Test-Runs {
    param([string]$Path)
    try {
        $p = Start-Process -FilePath $Path -ArgumentList @('version') -NoNewWindow -Wait -PassThru -ErrorAction Stop
        return ($p.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Install-DesktopIntegration {
    param([string]$InstallDir)
    # Start Menu shortcut is genuinely useful on Windows; the icon is optional
    # and must never be able to fail the CLI install.
    try {
        $start = [Environment]::GetFolderPath('Programs')
        $lnkDir = Join-Path $start 'QYVORA'
        if (-not (Test-Path -LiteralPath $lnkDir)) { New-Item -ItemType Directory -Path $lnkDir -Force | Out-Null }
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut((Join-Path $lnkDir "$Tool.lnk"))
        $lnk.TargetPath = Join-Path $InstallDir "$Tool.exe"
        $lnk.WorkingDirectory = $InstallDir
        $lnk.Description = $AppComment
        $lnk.Save()
        Write-Ok "Start Menu shortcut: $lnkDir\$Tool.lnk"
    } catch {
        Write-Warn "Could not create a Start Menu shortcut; CLI installation is unaffected."
    }
    return 0
}

function Invoke-Uninstall {
    $dir = Get-InstallDir
    $exe = Join-Path $dir "$Tool.exe"
    $removed = $false
    if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force; Write-Ok "Removed $exe"; $removed = $true }
    else { Write-Info "No binary at $exe" }

    try {
        $start = [Environment]::GetFolderPath('Programs')
        $lnk = Join-Path (Join-Path $start 'QYVORA') "$Tool.lnk"
        if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force; Write-Ok 'Removed Start Menu shortcut' }
    } catch { }

    if (Test-OnUserPath $dir) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $kept = ($userPath -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ine $dir.TrimEnd('\') })
        [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
        Write-Ok "Removed $dir from your user PATH"
    }
    if ($removed) { Write-Ok "$ToolTitle removed." } else { Write-Info "$ToolTitle was not installed." }
    Write-Note 'Configuration and scan data were left untouched.'
    exit $ExitOk
}

# === main ===
Write-Host ''
Write-Host "  $ToolTitle CLI - QYVORA Installer for Windows" -ForegroundColor Cyan
Write-Host '  QYVORA OffSec - Tamale, Ghana' -ForegroundColor Cyan
Write-Host ''

if ($Uninstall) { Invoke-Uninstall }

$arch = Get-ToolTarget
if ($arch -eq 'unsupported') {
    Stop-With $ExitUnsupported "Unsupported CPU architecture: $env:PROCESSOR_ARCHITECTURE"
}
if ($arch -eq 'i386') {
    Stop-With $ExitUnsupported '32-bit (x86) Windows builds are not published. Use 64-bit Windows.'
}

$installDir = Get-InstallDir
$artifact = Get-ArtifactName $arch

if ([string]::IsNullOrEmpty($Version)) {
    $baseUrl = "https://github.com/$Repo/releases/latest/download"
} else {
    if ($Version -notmatch '^[A-Za-z0-9._-]+$') { Stop-With $ExitFatal "Invalid release tag: $Version" }
    $baseUrl = "https://github.com/$Repo/releases/download/$Version"
}

Write-Host ''
Write-Info "Detected windows/$arch"
Write-Info "Install directory: $installDir"

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("qyvora-" + $Tool + "-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    $downloaded = Join-Path $work $artifact
    $usePrebuilt = -not $FromSource

    if ($usePrebuilt) {
        Write-Info "Downloading $artifact..."
        if (Invoke-Download "$baseUrl/$artifact" $downloaded) {
            $sums = Join-Path $work 'checksums.txt'
            if (-not (Invoke-Download "$baseUrl/checksums.txt" $sums)) {
                Stop-With $ExitVerify 'Could not download checksums.txt; refusing to install an unverified artifact.'
            }
            if (-not (Test-Checksum $downloaded $artifact $sums)) {
                Stop-With $ExitVerify 'Checksum verification failed. Nothing was installed.'
            }
            if (-not (Test-Executable $downloaded $arch)) {
                Stop-With $ExitVerify "Artifact $artifact is not compatible with windows/$arch. Nothing was installed."
            }
        } else {
            $usePrebuilt = $false
            Write-Warn "No published artifact named $artifact."
        }
    }

    if (-not $usePrebuilt) {
        if ($SourceBuild -ne '1') {
            Stop-With $ExitUnsupported "$ToolTitle has no release artifact for windows/$arch and offers no source build."
        }
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
            Write-Err "Building from source requires Go $MinGo+."
            Write-Note "Download it from https://go.dev/dl/ and re-run this installer."
            exit $ExitFatal
        }
        $srcRoot = if (Test-Path (Join-Path $PWD 'go.mod')) { $PWD.Path } else { $null }
        if (-not $srcRoot) {
            Stop-With $ExitFatal 'Source builds must run from a checkout of the repository (no go.mod here).'
        }
        Write-Info 'Building from the local checkout...'
        $downloaded = Join-Path $work "$Tool.exe"
        Push-Location $srcRoot
        try {
            $env:CGO_ENABLED = '0'
            & go build -trimpath -ldflags '-s -w' -o $downloaded $MainPkg
            if ($LASTEXITCODE -ne 0) { Stop-With $ExitFatal 'Source build failed.' }
        } finally { Pop-Location }
        if (-not (Test-Executable $downloaded $arch)) {
            Stop-With $ExitVerify 'The locally built binary does not match windows/$arch.'
        }
    }

    # Execute before touching the live install.
    if (-not (Test-Runs $downloaded)) {
        Stop-With $ExitVerify 'The downloaded binary cannot execute on this machine. Nothing was installed.'
    }
    Write-Ok 'Artifact executes on this machine'

    if (-not (Test-Path -LiteralPath $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    $dest = Join-Path $installDir "$Tool.exe"
    $staging = Join-Path $installDir ".$Tool.new.$PID"
    $backup = $null
    if (Test-Path -LiteralPath $dest) {
        $backup = Join-Path $installDir ".$Tool.old.$PID"
        Copy-Item -LiteralPath $dest -Destination $backup -Force
    }
    Copy-Item -LiteralPath $downloaded -Destination $staging -Force
    Move-Item -LiteralPath $staging -Destination $dest -Force

    if (-not (Test-Runs $dest)) {
        Write-Err "The installed binary at $dest cannot run on this machine."
        if ($backup) {
            Move-Item -LiteralPath $backup -Destination $dest -Force
            Write-Ok 'Rolled back to the previous working installation.'
        } else {
            Remove-Item -LiteralPath $dest -Force
            Write-Err 'No previous installation existed, so nothing was left behind.'
        }
        exit $ExitVerify
    }
    if ($backup) { Remove-Item -LiteralPath $backup -Force }

    Add-ToUserPath $installDir
    Install-DesktopIntegration $installDir | Out-Null

    Write-Host ''
    Write-Host '  Installation' -ForegroundColor White
    Write-Host "    [OK] Binary installed to $dest"
    Write-Host "    [OK] PATH contains $installDir"
    Write-Host ''
    Write-Ok "$ToolTitle installed successfully."
    Write-Note "Run '$Tool version' to confirm."
    exit $ExitOk
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
