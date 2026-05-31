# Downloads nlohmann/json single-header into sniffer_core.
$version = "3.12.0"
$dest = Join-Path $PSScriptRoot "json.hpp"
$url = "https://github.com/nlohmann/json/releases/download/v$version/json.hpp"

if (Test-Path $dest) {
    Write-Host "json.hpp already present; skipping download."
    return
}

Write-Host "Downloading nlohmann/json v$version ..."
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
Write-Host "Done: $dest"
