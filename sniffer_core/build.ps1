param(
    [string]$NpcapSdkDir = $env:NPCAP_SDK_DIR
)

$ErrorActionPreference = "Stop"

if (-not $NpcapSdkDir) {
    $candidates = @(
        "C:\npcap-sdk",
        (Join-Path $env:ProgramFiles "Npcap\sdk"),
        (Join-Path $PSScriptRoot "vendor\npcap-sdk")
    )
    $NpcapSdkDir = $candidates |
        Where-Object { Test-Path (Join-Path $_ "Include\pcap\pcap.h") } |
        Select-Object -First 1
}

if (-not $NpcapSdkDir) {
    & (Join-Path $PSScriptRoot "fetch_npcap_sdk.ps1")
    if (-not $?) { exit 1 }
    $NpcapSdkDir = Join-Path $PSScriptRoot "vendor\npcap-sdk"
}

& (Join-Path $PSScriptRoot "fetch_deps.ps1")
if (-not $?) { exit 1 }

$buildDir = Join-Path $PSScriptRoot "build"
cmake -S $PSScriptRoot -B $buildDir `
    -DCMAKE_BUILD_TYPE=Release `
    -DCOPY_TO_TAURI=ON `
    "-DNPCAP_SDK_DIR=$NpcapSdkDir"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $buildDir --config Release
exit $LASTEXITCODE
