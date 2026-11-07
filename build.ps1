$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (!(Test-Path -LiteralPath $python)) { throw 'Create .venv and install requirements-build.txt first.' }
$driverDir = Join-Path $PSScriptRoot 'drivers'
New-Item -ItemType Directory -Force -Path $driverDir | Out-Null
$hashes = @{
    'WinRing0x64.sys' = '11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5'
    'ThrottleStop.sys' = '16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0'
}
$base = 'https://raw.githubusercontent.com/skbskhud/p104-unlock-v3/ef45a8d3dd4cdbcde6a4611dd9ecda75ac4efb56/P104-2.0x16-v1.2/bin/drivers'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
foreach ($name in $hashes.Keys) {
    $target = Join-Path $driverDir $name
    if (!(Test-Path -LiteralPath $target)) { Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $target }
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$name]) { throw "Driver hash mismatch: $name" }
}
& $python -m unittest discover -s src -p test_minimal.py
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
& $python -m PyInstaller --noconfirm --clean --onefile --windowed --name P102Gen2 --add-data "$driverDir;drivers" src/app.py
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
Write-Host 'Built dist\P102Gen2.exe'
