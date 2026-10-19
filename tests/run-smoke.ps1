# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Real-consumer smoke scenario (one of the tests/ integration suite).
#
# Restores the freshly packed per-RID Microsoft.JavaScript.V8.<rid>.<version>.nupkg
# from out/pkg, msbuilds tests/consumer.vcxproj as the requested Configuration|x64
# against it, and runs the resulting v8jsi_smoke.exe with no args - which evals
# `1 + 2` through the JSI ABI runtime and asserts 3, plus four cross-CRT exercises
# (utf8 round-trip, global property set/get, HostFunction call, JSError catch).
#
# -UseV8Sandbox additionally validates the sandbox package surface: it sets
# /p:UseV8Sandbox=true (the package .targets add the v8host include dir +
# v8host.dll.lib and copy v8jsisb.dll / sbox.exe / v8host.dll) and the EXE then
# drives v8jsisb.dll through JSI and runs a session through the client API. Use it
# only when the restored package actually carries the sandbox binaries.
# consumer.vcxproj puts the EXE and copy-local payload in
# bin\<Configuration>\<Platform>\ (x64 or arm64 for sandbox consumers).
#
# Exit codes:
#   0 = smoke green
#   non-0 = any failure (no .nupkg, restore/build/run failure, EXE assert)
#
# Run after a successful `node scripts/build.ts --no-build --pack` so out/pkg
# contains a freshly-packed .nupkg. Shared restore/build logic lives in
# test-helpers.ps1.

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$Configuration = 'Release',
    [string]$Platform = 'x64',
    [string]$PkgDir,
    [switch]$UseV8Sandbox
)

$ErrorActionPreference = 'Stop'
$harnessDir = $PSScriptRoot
if (-not $harnessDir) { $harnessDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $harnessDir '..')).Path }
. (Join-Path $harnessDir 'test-helpers.ps1')

$PkgDir = Get-PkgDir -RepoRoot $RepoRoot -PkgDir $PkgDir
$rid = Get-Rid -Platform $Platform
$pkg = Restore-V8Package -HarnessDir $harnessDir -PkgDir $PkgDir -Rid $rid

if ($UseV8Sandbox) {
    # Exercise only the package validation target: no compilation or binary copy.
    $msbuild = Get-MSBuild
    $invalidOutDir = Join-Path $harnessDir 'bin\invalid-sandbox-layout'
    $validation = & $msbuild (Join-Path $harnessDir 'consumer.vcxproj') `
        "/t:V8HostSandboxValidateOutputDirectory_$rid" `
        "/p:Configuration=$Configuration" "/p:Platform=$Platform" `
        "/p:V8JsiPackageProps=$($pkg.PkgProps)" `
        "/p:V8JsiPackageTargets=$($pkg.PkgTargets)" `
        "/p:V8JsiRuntimeIdentifier=$rid" /p:UseV8Sandbox=true `
        "/p:OutDir=$invalidOutDir" /nologo /v:minimal 2>&1
    $validationExit = $LASTEXITCODE
    $validation | Out-Host
    if ($validationExit -eq 0 -or ($validation -join "`n") -notmatch 'V8HOST001') {
        throw 'Expected invalid sandbox output directory to fail with V8HOST001.'
    }
    Write-Host 'tests: invalid sandbox output directory rejected (V8HOST001)'
}

$exe = Build-Consumer -HarnessDir $harnessDir -Configuration $Configuration `
    -Platform $Platform -Rid $rid -PkgProps $pkg.PkgProps -PkgTargets $pkg.PkgTargets `
    -UseV8Sandbox:$UseV8Sandbox

Write-Host "tests: running $exe"
& $exe
if ($LASTEXITCODE -ne 0) { throw "v8jsi_smoke.exe failed (exit $LASTEXITCODE)" }
Write-Host "tests: smoke OK"
