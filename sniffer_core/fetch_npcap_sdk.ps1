# ES: Descarga el SDK publico de Npcap en la cache local. / EN: Downloads the public Npcap SDK into the local cache.
$version = "1.16"
$vendorDir = Join-Path $PSScriptRoot "vendor"
$dest = Join-Path $vendorDir "npcap-sdk"
$archive = Join-Path $vendorDir "npcap-sdk-$version.zip"
$url = "https://npcap.com/dist/npcap-sdk-$version.zip"

if (Test-Path (Join-Path $dest "Include\pcap\pcap.h")) {
    Write-Host "Npcap SDK already present; skipping download."
    return
}

New-Item -ItemType Directory -Path $vendorDir -Force | Out-Null
Write-Host "Downloading Npcap SDK $version ..."
Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing

if (Test-Path $dest) {
    Remove-Item -LiteralPath $dest -Recurse -Force
}

Expand-Archive -LiteralPath $archive -DestinationPath $dest -Force
Remove-Item -LiteralPath $archive -Force

if (-not (Test-Path (Join-Path $dest "Include\pcap\pcap.h"))) {
    throw "Npcap SDK archive does not contain Include\pcap\pcap.h."
}

Write-Host "Done: $dest"
