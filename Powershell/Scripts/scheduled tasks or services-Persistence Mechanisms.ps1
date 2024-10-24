# List Scheduled tasks:
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }

# Monitor Services
Get-Service | Where-Object { $_.StartType -eq 'Automatic' }