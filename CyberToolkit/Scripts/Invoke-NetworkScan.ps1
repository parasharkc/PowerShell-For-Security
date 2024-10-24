# Invoke-NetworkScan.ps1

# Import the custom module
Import-Module "C:\Users\Parashar11\CyberToolkit\Modules\NetworkScanner.psm1"

# Define the subnet to scan (change this to your actual subnet)
$subnet = "192.168.1"

# Run the network scan
$activeDevices = Scan-Subnet -subnet $subnet

# Output the list of active devices
Write-Output "Scan complete. Active devices:"
$activeDevices | ForEach-Object { Write-Output $_ }
