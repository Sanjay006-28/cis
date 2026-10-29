# PowerShell helper to stop all running malware analysis servers
$ports = @(8001, 5173, 8501)
$stopped = $false

foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and ($proc.ProcessName -match 'python|node')) {
            Write-Host "Stopping $($proc.ProcessName) (PID $($proc.Id)) on port $port..." -ForegroundColor Yellow
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            $stopped = $true
        }
    }
}

if (-not $stopped) {
    Write-Host "No active servers were found running." -ForegroundColor Green
} else {
    Write-Host "All servers stopped successfully." -ForegroundColor Green
}
