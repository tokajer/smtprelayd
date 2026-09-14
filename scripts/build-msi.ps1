# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Tokajer
#
# Builds the MSI and the setup.exe bootstrapper on a Windows machine, with the
# same candle/light invocations .github/workflows/release.yml uses. It exists
# for the case CI cannot serve: a test build of an uncommitted change, or a
# build from an unpacked distribution zip that has no repository and no Go
# toolchain in it -- the compiled smtprelayd.exe is the input here, not the
# source tree.
#
# The ProductVersion must be higher than the installed one. smtprelayd.wxs
# declares MajorUpgrade without AllowSameVersionUpgrades, so an MSI carrying
# the version that is already installed is not an upgrade: it installs a
# second product with the same UpgradeCode, which is how a duplicate service
# registration appears. Only the first three fields of a ProductVersion are
# compared, so 0.5.3.1 does not count as newer than 0.5.3 either -- hence the
# three-field check below.

[CmdletBinding()]
param(
    # MSI ProductVersion. Not the Go binary's own version string, which is
    # fixed at compile time and is whatever `smtprelayd version` reports.
    [string]$Version = "0.5.4",

    # WiX v3 bin directory. Defaults to $env:WIX\bin, which the toolset's
    # installer sets machine-wide.
    [string]$WixBin,

    # Root of the unpacked distribution (or repository) holding bin\,
    # configs\ and packaging\. Defaults to this script's parent directory.
    [string]$Root
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must be MAJOR.MINOR.PATCH (only those three fields are compared for upgrades), got: $Version"
}

if (-not $Root) {
    $Root = Split-Path -Parent $PSScriptRoot
}
$Root = (Resolve-Path $Root).Path

if (-not $WixBin) {
    if ($env:WIX) {
        $WixBin = Join-Path $env:WIX "bin"
    } else {
        $candidates = @(
            "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin"
        )
        $WixBin = $candidates | Where-Object { $_ -and (Test-Path (Join-Path $_ "candle.exe")) } | Select-Object -First 1
    }
}
if (-not $WixBin -or -not (Test-Path (Join-Path $WixBin "candle.exe"))) {
    throw @"
WiX Toolset v3.14 not found. Install it (wix314.exe from
https://github.com/wixtoolset/wix3/releases) and run this again, or pass the
path explicitly:  .\build-msi.ps1 -WixBin "C:\Program Files (x86)\WiX Toolset v3.14\bin"
"@
}

$binary = Join-Path $Root "bin\smtprelayd-windows-amd64.exe"
$config = Join-Path $Root "configs\smtprelayd.example.toml"
$wxs = Join-Path $Root "packaging\windows\smtprelayd.wxs"
$bundleWxs = Join-Path $Root "packaging\windows\smtprelayd-bundle.wxs"
$theme = Join-Path $Root "packaging\windows\smtprelayd-bundle-theme.xml"
foreach ($f in @($binary, $config, $wxs, $bundleWxs, $theme)) {
    if (-not (Test-Path $f)) { throw "missing input: $f" }
}

$obj = Join-Path $Root "obj"
$dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $obj, $dist | Out-Null

$msi = Join-Path $dist "smtprelayd-$Version-amd64.msi"
$setup = Join-Path $dist "smtprelayd-$Version-amd64-setup.exe"

Write-Host "WiX      : $WixBin"
Write-Host "Version  : $Version"
Write-Host "Binary   : $binary"
Write-Host ""

# -ext WixUIExtension is linked for the stock ExitDialog/UserExit/FatalError
# dialogs and WixUI_ErrorProgressText, not for a full wizard; -sice:ICE20 goes
# with that, because ICE20 demands the complete standard dialog set once any
# custom dialog is authored. Both match the release workflow exactly.
& "$WixBin\candle.exe" -ext WixUtilExtension -ext WixUIExtension `
    -dVersion="$Version" `
    -dBinaryPath="$binary" `
    -dExampleConfigPath="$config" `
    -out "$obj\smtprelayd.wixobj" "$wxs"
if ($LASTEXITCODE -ne 0) { throw "candle.exe failed" }

& "$WixBin\light.exe" -ext WixUtilExtension -ext WixUIExtension `
    -sice:ICE20 `
    -out "$msi" "$obj\smtprelayd.wixobj"
if ($LASTEXITCODE -ne 0) { throw "light.exe failed" }

& "$WixBin\candle.exe" -ext WixBalExtension `
    -dVersion="$Version" `
    -dMsiPath="$msi" `
    -dThemeFile="$theme" `
    -out "$obj\smtprelayd-bundle.wixobj" "$bundleWxs"
if ($LASTEXITCODE -ne 0) { throw "candle.exe (bundle) failed" }

& "$WixBin\light.exe" -ext WixBalExtension `
    -out "$setup" "$obj\smtprelayd-bundle.wixobj"
if ($LASTEXITCODE -ne 0) { throw "light.exe (bundle) failed" }

Write-Host ""
foreach ($f in @($msi, $setup)) {
    $h = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()
    Write-Host ("{0}  {1}" -f $h, (Split-Path -Leaf $f))
}
Write-Host ""
Write-Host "Install from an ALREADY elevated PowerShell (open it with 'Run as"
Write-Host "administrator' first). Letting msiexec elevate on demand triggers"
Write-Host "Windows' MSI_LUA shim, which suppresses the progress dialog and the"
Write-Host "uninstall-time purge question - see PROGRESS.md, 2026-08-21."
