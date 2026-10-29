# PowerShell helper to invoke run.bat
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $scriptDir "backend\main.py")) {
    $projDir = $scriptDir
} elseif (Test-Path (Join-Path $scriptDir "malware\backend\main.py")) {
    $projDir = Join-Path $scriptDir "malware"
} else {
    $projDir = $scriptDir
}
Set-Location $projDir
& cmd.exe /c (Join-Path $projDir "run.bat")
