# Define a folder to monitor (e.g., sensitive documents folder)
$watchFolder = "C:\Users\Parashar11\Powershell\File Access Monitoring\Secured File.txt"

# Define a log file to store suspicious events
$logFilePath = "C:\Users\Parashar11\Powershell\File Access Monitoring\ExfiltrationLog.txt"

# Function to monitor file accesses
function Monitor-FileAccess {
    # Use Get-EventLog to track file access
    $eventLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} | 
    Where-Object { $_.Properties[6].Value -like "$watchFolder*" }

    foreach ($event in $eventLogs) {
        # Get timestamp and details of the event
        $time = $event.TimeCreated
        $fileName = $event.Properties[6].Value
        $user = $event.Properties[1].Value

        # Log file access details
        $log = "${time}: User $user accessed $fileName"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged file access: $log"
    }
}

# Run the file access monitor periodically
while ($true) {
    Monitor-FileAccess
    Start-Sleep -Seconds 30  # Adjust the frequency as needed
}