Get-NetTCPConnection

# Define a list of known malicious IP addresses
$suspiciousIPs = @("203.0.113.1", "198.51.100.23")

# Function to monitor network traffic
function Monitor-NetworkTraffic {
    $connections = Get-NetTCPConnection | 
    Where-Object { $_.RemoteAddress -in $suspiciousIPs }

    foreach ($conn in $connections) {
        $time = Get-Date
        $remoteIP = $conn.RemoteAddress
        $localIP = $conn.LocalAddress

        # Log suspicious connections
        $log = "${time}: Suspicious connection detected! Local IP: $localIP, Remote IP: $remoteIP"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged suspicious connection: $log"
    }
}

# Monitor network traffic periodically
while ($true) {
    Monitor-NetworkTraffic
    Start-Sleep -Seconds 30
}