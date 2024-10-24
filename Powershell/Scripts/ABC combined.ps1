# Define paths and parameters
$watchFolder = $watchFolder = "C:\Users\Parashar11\Powershell\File Access Monitoring\Secured File.txt"
$logFilePath = "C:\Users\Parashar11\Powershell\File Access Monitoring\ExfiltrationLog.txt"
$sizeThreshold = 50MB
$suspiciousIPs = @("203.0.113.1", "198.51.100.23")

function Monitor-FileAccess {
    $eventLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} | 
    Where-Object { $_.Properties[6].Value -like "$watchFolder*" }

    foreach ($event in $eventLogs) {
        $time = $event.TimeCreated
        $fileName = $event.Properties[6].Value
        $user = $event.Properties[1].Value
        $log = "${time}: User $user accessed $fileName"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged file access: $log"
    }
}

function Monitor-LargeFileTransfers {
    $files = Get-ChildItem -Path $watchFolder -Recurse | 
    Where-Object { $_.Length -gt $sizeThreshold }

    foreach ($file in $files) {
        $time = Get-Date
        $fileSizeMB = [math]::Round(($file.Length / 1MB), 2)
        $log = "${time}: Large file detected: $($file.FullName), Size: $fileSizeMB MB"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged large file transfer: $log"
    }
}

function Monitor-NetworkTraffic {
    $connections = Get-NetTCPConnection | 
    Where-Object { $_.RemoteAddress -in $suspiciousIPs }

    foreach ($conn in $connections) {
        $time = Get-Date
        $remoteIP = $conn.RemoteAddress
        $localIP = $conn.LocalAddress
        $log = "${time}: Suspicious connection detected! Local IP: $localIP, Remote IP: $remoteIP"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged suspicious connection: $log"
    }
}

# Run the combined monitoring script periodically
while ($true) {
    Monitor-FileAccess
    Monitor-LargeFileTransfers
    Monitor-NetworkTraffic
    Start-Sleep -Seconds 30
}