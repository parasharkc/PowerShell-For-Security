# FileIntegrityMonitor.psm1

Function Get-FileHashValue {
    param (
        [string]$filePath
    )
    if (Test-Path $filePath) {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        return $hash.Hash
    } else {
        Write-Error "File not found!"
    }
}

Function Monitor-FileChanges {
    param (
        [string]$filePath,
        [string]$hashFile
    )
    $currentHash = Get-FileHashValue -filePath $filePath
    $storedHash = Get-Content -Path $hashFile

    if ($currentHash -ne $storedHash) {
        Write-Output "File has been changed."
        Set-Content -Path $hashFile -Value $currentHash
    } else {
        Write-Output "File is unchanged."
    }
}
