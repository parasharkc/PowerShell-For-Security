# NetworkScanner.psm1
function Scan-Subnet {
    param (
        [string]$subnet
    )

    $pingResults = @()

    # Iterate through the IP range (e.g., 1-254)
    for ($i = 1; $i -le 254; $i++) {
        $ipAddress = "$subnet.$i"

        # Ping each IP address once
        $result = Test-Connection -ComputerName $ipAddress -Count 1 -Quiet
        if ($result) {
            Write-Output "Device found at $ipAddress"
            $pingResults += $ipAddress
        }
    }

    # Return the list of active IPs
    return $pingResults
}

Export-ModuleMember -Function Scan-Subnet
