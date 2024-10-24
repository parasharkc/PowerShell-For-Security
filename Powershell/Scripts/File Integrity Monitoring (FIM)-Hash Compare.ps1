# Set the paths to your files
$filePath = "C:\Users\Parashar11\Powershell\File Integrity Monitoring\Important File.txt"
$hashFilePath = "C:\Users\Parashar11\Powershell\File Integrity Monitoring\hash.txt"

# Step 2: Function to monitor the file for changes
function Monitor-FileChange {
    param (
        [string]$filePath,
        [string]$hashFilePath
    )
     # Get the current hash of the file
    $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
    Write-Host "Current Hash: $currentHash"

    # Read the stored original hash from the hash file
    $storedHash = Get-Content -Path $hashFilePath
    Write-Host "Stored Hash: $storedHash"

    # Compare the hashes
    if ($currentHash -ne $storedHash) {
        Write-Host "File has been modified!"
        
        # Log the modification with a timestamp
        $currentTime = Get-Date
        $alert = "${currentTime}: File $filePath has been modified!" 
        Add-Content -Path "C:\Users\Parashar11\Powershell\File Integrity Monitoring\log.txt" -Value $alert
   
 
        # Optional: You can uncomment the email alert if needed
        # Send-MailMessage -From "you@example.com" -To "admin@example.com" -Subject "File Change Detected" -Body $alert -SmtpServer "smtp.example.com"
    } else {
        Write-Host "File is unchanged."
    }
}

# Step 3: Call the function to monitor the file for changes
Monitor-FileChange -filePath $filePath -hashFilePath $hashFilePath