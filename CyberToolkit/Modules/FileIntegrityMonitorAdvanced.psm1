Function Monitor-FileChanges {
    param (
        [string]$filePath,
        [string]$hashFile
    )

    $logFile = "C:\Users\Parashar11\CyberToolkit\Logs\toolkit.log"
    $currentTime = Get-Date

    Try {
        $currentHash = Get-FileHashValue -filePath $filePath
        $storedHash = Get-Content -Path $hashFile

        if ($currentHash -ne $storedHash) {
            Write-Output "${currentTime}: File has been changed."
            Set-Content -Path $hashFile -Value $currentHash
            Add-Content -Path $logFile -Value "${currentTime}: File changed - $filePath"
        } else {
            Write-Output "${currentTime}: File is unchanged."
            Add-Content -Path $logFile -Value "${currentTime}: File unchanged - $filePath"
        }
    }
    Catch {
        Write-Error "${currentTime}: Error occurred. $_"
        Add-Content -Path $logFile -Value "${currentTime}: Error occurred - $_"
    }
}
