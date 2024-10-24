for ($i=1; $i -le 254; $i++) {
    $ip = "192.168.1.$i"
    if (Test-Connection -ComputerName $ip -Quiet -Count 1) {
        Write-Host "$ip is online"
    } else {
        Write-Host "$ip is offline"
    }
}