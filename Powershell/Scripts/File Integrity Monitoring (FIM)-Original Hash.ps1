# Set the paths to your files
$filePath = "C:\Users\Parashar11\Powershell\File Integrity Monitoring\Important File.txt"
$hashFilePath = "C:\Users\Parashar11\Powershell\File Integrity Monitoring\hash.txt"

# Step 1: Generate the initial hash and store it (run this part only once to generate the original hash)
$originalHash = Get-FileHash -Path $filePath -Algorithm SHA256
$originalHash.Hash | Out-File -FilePath $hashFilePath

