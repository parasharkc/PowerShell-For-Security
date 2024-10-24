Import-Module "C:\Users\Parashar11\CyberToolkit\Modules\UserAudit.psm1"

$users = Get-LocalUserAudit
$users | Format-Table
