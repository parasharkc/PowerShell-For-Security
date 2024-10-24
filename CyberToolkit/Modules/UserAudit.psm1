# UserAudit.psm1

Function Get-LocalUserAudit {
    Get-LocalUser | ForEach-Object {
        [PSCustomObject]@{
            Username       = $_.Name
            LastLogon      = $_.LastLogon
            Enabled        = $_.Enabled
            PasswordExpired = $_.PasswordExpired
        }
    }
}
