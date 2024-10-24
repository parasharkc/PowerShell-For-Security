Get-LocalGroupMember -Group "Administrators"
$admins = Get-LocalGroupMember -Group "Administrators"
$admins | Export-Csv "C:\Users\Parashar11\Powershell\AdminList.csv" -NoTypeInformation