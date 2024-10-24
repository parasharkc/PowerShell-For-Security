# Define size threshold for detecting large file transfers (e.g., 50MB)
$sizeThreshold = 50MB

# Function to monitor file size and detect large file transfers
$watchFolder = "C:\Users\Parashar11\Powershell\File Access Monitoring\Secured File.txt"
function Monitor-LargeFileTransfers {
    $files = Get-ChildItem -Path $watchFolder -Recurse | 
    Where-Object { $_.Length -gt $sizeThreshold }

    foreach ($file in $files) {
        $time = Get-Date
        $fileSizeMB = [math]::Round(($file.Length / 1MB), 2)

        # Log large file transfers
        $log = "${time}: Large file detected: $($file.FullName), Size: $fileSizeMB MB"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged large file transfer: $log"
    }
}

# Monitor large file transfers periodically
while ($true) {
    Monitor-LargeFileTransfers
    Start-Sleep -Seconds 30
}
