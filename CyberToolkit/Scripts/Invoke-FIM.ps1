Import-Module "C:\Users\Parashar11\CyberToolkit\Modules\FileIntegrityMonitor.psm1"

$filePath = "C:\Users\Parashar11\CyberToolkit\ImportantFile.txt"
$hashFile = "C:\Users\Parashar11\CyberToolkit\Logs\filehash.txt"

Monitor-FileChanges -filePath $filePath -hashFile $hashFile
