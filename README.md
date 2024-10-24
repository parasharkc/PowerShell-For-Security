# PowerShell-For-Security

## Objective

The primary objective of this project is to utilize PowerShell scripting to enhance automation and streamline various cybersecurity tasks. The scripts were designed to:
- Monitor system processes and network activities.
- Detect security vulnerabilities or suspicious behavior.
- Identify software and system configurations that may lead to security issues.
- Provide incident response capabilities, such as logging and file integrity monitoring.
- Automate repetitive security tasks to minimize human error.
- Build modular and reusable PowerShell functions
  
By the end of the project, the goal is to build a comprehensive toolkit of PowerShell scripts that can assist in real-time monitoring, detection, and response for cybersecurity threats.



### Skills Learned

- PowerShell Scripting: Writing and automating cybersecurity tasks through PowerShell cmdlets.
- Cybersecurity Monitoring: Understanding critical cybersecurity tasks such as process monitoring, file integrity, privilege escalation detection, and suspicious network traffic monitoring.
- System and Network Forensics: Gathering system information, identifying anomalies, and logging key events for forensic analysis.
- Modular Programming: Organized scripts for better maintenance, scaling, and debugging, separating core functions from script execution.
- Automation: Building automated tasks that can monitor system behavior and detect potential attacks or security breaches.
- Threat Detection: Implementing scripts that focus on monitoring and responding to common attack vectors.

### Tools Used

- PowerShell (Version 5.1 and above): Core scripting tool used to develop and run all scripts.
- Windows Event Logs: For log analysis and suspicious activity detection.
- Network tools: Integrated PowerShell cmdlets for network scanning.
- File Integrity Monitoring tools: Using hashing algorithms (SHA256) for file integrity checks.
- Custom Modules (.psm1): For creating reusable functions for file integrity monitoring, network scanning, and user auditing.
- Scripts (.ps1): To invoke the modular functions for specific tasks.
- Task Scheduler: Monitoring scheduled tasks or services for persistence detection.

## Detailed Breakdown of Scripts and Steps:
**NOTE: Please replace path with your own location.**


**1. Process Monitoring Script**

_Objective_: Continuously monitor running processes and flag unauthorized or suspicious processes.

_Steps_:
- Use the Get-Process cmdlet to list all running processes.
- Use the Export-Csv cmdlet to export report to our desired path. 
- Log or alert if unknown or suspicious processes are detected.
- Furthermore, we can create our own whitelist of processes and Compare the processes against a whitelist of known safe processes.

_Key Script_:
```
Get-Process
Get-Process | Export-Csv -Path "C:\Users\Parashar11\Powershell\process_list.csv" -NoTypeInformation
```
```
$whitelist = @("explorer", "svchost", "chrome")
Get-Process | ForEach-Object {
    if ($_ -notin $whitelist) {
        Write-Host "Suspicious process detected: $($_.Name)"
    }
}
```
<img width="1440" alt="Screenshot 2024-10-24 at 3 52 20 PM" src="https://github.com/user-attachments/assets/5ef6df01-d237-44a0-9501-99095f89ff9b">

**2. Installed Software Check**

_Objective_: Detect and log all installed software on the system.

_Steps_:
- Use the Get-WmiObject cmdlet to retrieve information on installed software.
- Log software details to identify unauthorized software installations.
  
_Key Script_:
```
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Export-Csv -Path "C:\Users\Parashar11\Powershell\installed_software.csv" -NoTypeInformation
```

<img width="863" alt="Screenshot 2024-10-24 at 4 03 05 PM" src="https://github.com/user-attachments/assets/1d291e49-c1dc-4e55-8d99-4cff9fa9ea7b">

**3. Network Scanner**

_Objective_: Scan the network to identify live hosts and open ports.

_Steps_:
- Use PowerShell's Test-Connection to scan for live hosts. 
- Or, use PowerShell's Test-NetConnection to scan for live hosts and common open ports.
- Log results for further analysis.
  
_Key Script_:
```
for ($i=1; $i -le 254; $i++) {
    $ip = "192.168.1.$i"
    if (Test-Connection -ComputerName $ip -Quiet -Count 1) {
        Write-Host "$ip is online"
    } else {
        Write-Host "$ip is offline"
    }
}
```
```
1..255 | ForEach-Object {
    $ip = "192.168.1.$_"
    Test-NetConnection -ComputerName $ip -Port 80
}
```
<img width="785" alt="Screenshot 2024-10-24 at 4 10 58 PM" src="https://github.com/user-attachments/assets/4e7705a3-39f2-4ae4-af74-460310a622dc">

**4. Log Analysis**

_Objective_: Analyze system logs to detect unauthorized login attempts or suspicious activities.

_Steps_:
- Retrieve and filter Windows event logs using Get-EventLog.
- Search for specific event IDs related to security breaches (e.g., failed login attempts).

_Key Script_:
```
Get-EventLog -LogName Security -InstanceId 4625 | Out-File "failed_logins.txt"
```

**5. File Integrity Monitoring**

_Objective_: Monitor files for any unauthorized modifications.

_Steps_:
- Use PowerShell to generate file hashes.
- Safely store it. 
- Regularly compare hashes to detect changes.

Key Script:
```
# Set the paths to your files
$filePath = "C:\Users\Parashar11\Powershell\File Integrity Monitoring\Important File.txt"
$hashFilePath = "C:\Users\Parashar11\Powershell\File Integrity Monitoring\hash.txt"

# Step 1: Generate the initial hash and store it (run this part only once to generate the original hash)
$originalHash = Get-FileHash -Path $filePath -Algorithm SHA256
$originalHash.Hash | Out-File -FilePath $hashFilePath
```
<img width="1440" alt="Screenshot 2024-10-24 at 5 48 28 PM" src="https://github.com/user-attachments/assets/a8c4196d-9f87-49d2-a78a-f1abeca5c035">

```
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
```
<img width="1440" alt="Screenshot 2024-10-24 at 5 51 02 PM" src="https://github.com/user-attachments/assets/b919e97e-2719-4b97-ab12-a1306e76a0c3">

But if the file is changed, it will generate a different hash.

<img width="1440" alt="Screenshot 2024-10-24 at 5 53 09 PM" src="https://github.com/user-attachments/assets/e709adb7-cf73-407f-b487-2303691df2c4">

**6. Privilege Escalation Detection**

_Objective_: Detect unauthorized privilege escalations.

_Steps_:
- Monitor users and their associated privileges.
- Safely export to the csv file. 

_Key Script_:
```
Get-LocalGroupMember -Group "Administrators"
$admins = Get-LocalGroupMember -Group "Administrators"
$admins | Export-Csv "C:\Users\Parashar11\Powershell\AdminList.csv" -NoTypeInformation
```
<img width="1100" alt="Screenshot 2024-10-24 at 5 57 18 PM" src="https://github.com/user-attachments/assets/b416bd07-6da9-4f65-981e-d303c52d1ba7">

**7. Monitoring Scheduled Tasks/Services for Persistence**

_Objective_: Detect unauthorized scheduled tasks or services used for persistence.

_Steps_:
- Use Get-ScheduledTask to monitor scheduled tasks.
- Log suspicious tasks that could be used for persistence.
  
_Key Script_:
```
# List Scheduled tasks:
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }

# Monitor Services
Get-Service | Where-Object { $_.StartType -eq 'Automatic' }
```
<img width="1440" alt="Screenshot 2024-10-24 at 6 03 59 PM" src="https://github.com/user-attachments/assets/3dc3eb70-936a-41c9-89e6-92e4fdb29680">
<img width="1440" alt="Screenshot 2024-10-24 at 6 05 01 PM" src="https://github.com/user-attachments/assets/20597054-673b-409c-8afa-b041f38aa077">

**8. File Access Monitoring**

_Objective_: Monitor who accesses critical files and when.

_Steps_:
- Enable auditing on critical files.
- Use PowerShell to track file access events.
- Event ID 4663 – An Attempt Was Made To Access An Object

_Key Script_:
```
# Define a folder to monitor (e.g., sensitive documents folder)
$watchFolder = "C:\Users\Parashar11\Powershell\File Access Monitoring\Secured File.txt"

# Define a log file to store suspicious events
$logFilePath = "C:\Users\Parashar11\Powershell\File Access Monitoring\ExfiltrationLog.txt"

# Function to monitor file accesses
function Monitor-FileAccess {
    # Use Get-EventLog to track file access
    $eventLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} | 
    Where-Object { $_.Properties[6].Value -like "$watchFolder*" }

    foreach ($event in $eventLogs) {
        # Get timestamp and details of the event
        $time = $event.TimeCreated
        $fileName = $event.Properties[6].Value
        $user = $event.Properties[1].Value

        # Log file access details
        $log = "${time}: User $user accessed $fileName"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged file access: $log"
    }
}

# Run the file access monitor periodically
while ($true) {
    Monitor-FileAccess
    Start-Sleep -Seconds 30  # Adjust the frequency as needed
}
```

**9. Monitoring Large File Transfers**

_Objective_: Detect large file transfers, which could indicate data exfiltration.

_Steps_:
- Monitor network activity and file sizes.
- Alert when large file transfers occur.(50 MB)

_Key Script_:
```
# Define size threshold for detecting large file transfers (e.g., 50MB)
$sizeThreshold = 50MB

# Function to monitor file size and detect large file transfers
$watchFolder = "C:\Users\Parashar11\Powershell\File Access Monitoring\Secured File.txt"
function Monitor-LargeFileTransfers {
    $files = Get-ChildItem -Path $watchFolder -Recurse | 
    Where-Object { $_.Length -gt $sizeThreshold }

    foreach ($file in $files) {
        $time = Get-Date
        $fileSizeMB = [math]::Round(($file.Length / 1MB), 2)

        # Log large file transfers
        $log = "${time}: Large file detected: $($file.FullName), Size: $fileSizeMB MB"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged large file transfer: $log"
    }
}

# Monitor large file transfers periodically
while ($true) {
    Monitor-LargeFileTransfers
    Start-Sleep -Seconds 30
}
```

**10. Monitoring Suspicious Network Traffic**

_Objective_: Monitor network traffic for suspicious activity, such as unusual outbound connections.

_Steps_:
- Use Get-NetTCPConnection to monitor active network connections.
- Identify suspicious external connections based on IP addresses or geolocation.

_Key Script_:
```
Get-NetTCPConnection

# Define a list of known malicious IP addresses
$suspiciousIPs = @("203.0.113.1", "198.51.100.23")

# Function to monitor network traffic
function Monitor-NetworkTraffic {
    $connections = Get-NetTCPConnection | 
    Where-Object { $_.RemoteAddress -in $suspiciousIPs }

    foreach ($conn in $connections) {
        $time = Get-Date
        $remoteIP = $conn.RemoteAddress
        $localIP = $conn.LocalAddress

        # Log suspicious connections
        $log = "${time}: Suspicious connection detected! Local IP: $localIP, Remote IP: $remoteIP"
        Add-Content -Path $logFilePath -Value $log
        Write-Host "Logged suspicious connection: $log"
    }
}

# Monitor network traffic periodically
while ($true) {
    Monitor-NetworkTraffic
    Start-Sleep -Seconds 30
}
```
<img width="1440" alt="Screenshot 2024-10-24 at 6 16 58 PM" src="https://github.com/user-attachments/assets/5e90eede-62db-4360-a996-2f32027c436c">

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Cyber Toolkit
The creation of custom PowerShell toolkits using .psm1 and .ps1 files has allowed for modular, reusable, and scalable solutions to automate key cybersecurity tasks. The use of separate module files for the core functions ensures a clean separation of code and improves maintainability. The invocation scripts (.ps1) further enhance the usability of the toolkit by simplifying function execution for end-users. This modular design provides flexibility for extending and customizing the toolkit for different security environments, ultimately contributing to more efficient security monitoring, scanning, and auditing.

**1. File Integrity Monitor**

_Modular Function (File Integrity Monitoring - .psm1)_:
- Provides functions for hashing files and comparing them to baseline values.
- Uses SHA256 for file integrity checks.
  
_Steps_:
- Load the module using the Import-Module cmdlet.
- Create a function to hash the file and compare it with previously generated values.

_Key Script_:
```
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
```
_Invocation Script (Invoke-FIM - .ps1)_:
- Calls the Monitor-FileChanges function from the .psm1 module.
```
Import-Module "C:\Users\Parashar11\CyberToolkit\Modules\FileIntegrityMonitor.psm1"

$filePath = "C:\Users\Parashar11\CyberToolkit\ImportantFile.txt"
$hashFile = "C:\Users\Parashar11\CyberToolkit\Logs\filehash.txt"

Monitor-FileChanges -filePath $filePath -hashFile $hashFile
```

**2. Network Scanner Toolkit**

_Modular Function (Network Scanner - .psm1)_:
- Contains functions for network host discovery and port scanning.

_Steps_:
- Import the module for network scanning.
- The module can be reused for scanning different networks.
- Example Function in .psm1: Scan-Subnet

_Key Script_:
```
# NetworkScanner.psm1
function Scan-Subnet {
    param (
        [string]$subnet
    )

    $pingResults = @()

    # Iterate through the IP range (e.g., 1-254)
    for ($i = 1; $i -le 254; $i++) {
        $ipAddress = "$subnet.$i"

        # Ping each IP address once
        $result = Test-Connection -ComputerName $ipAddress -Count 1 -Quiet
        if ($result) {
            Write-Output "Device found at $ipAddress"
            $pingResults += $ipAddress
        }
    }

    # Return the list of active IPs
    return $pingResults
}

Export-ModuleMember -Function Scan-Subnet
```
_Invocation Script (Invoke-NetworkScan - .ps1)_:
- Calls the Scan-Subnet function from the .psm1 file.
```
# Invoke-NetworkScan.ps1

# Import the custom module
Import-Module "C:\Users\Parashar11\CyberToolkit\Modules\NetworkScanner.psm1"

# Define the subnet to scan (change this to your actual subnet)
$subnet = "192.168.1"

# Run the network scan
$activeDevices = Scan-Subnet -subnet $subnet

# Output the list of active devices
Write-Output "Scan complete. Active devices:"
$activeDevices | ForEach-Object { Write-Output $_ }
```

**3. User Audit Toolkit**

_Modular Function (User Audit - .psm1):_
- Audits user activity, including login times and administrative access.

Steps:
- Load the audit module and run the Get-LocalUserAudit function.
- Fetches Windows Event Log data for user logins and administrative tasks.

_Key Script_:
```
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
```
_Invocation Script (Invoke-UserAudit - .ps1)_:
- Calls the Get-LocalUserAudit function from the .psm1 file.
```
Import-Module "C:\Users\Parashar11\CyberToolkit\Modules\UserAudit.psm1"

$users = Get-LocalUserAudit
$users | Format-Table
```

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Automate PowerShell Scripts with Task Scheduler
You can execute PowerShell scripts through Task Scheduler. Windows Task Scheduler allows users to automate tasks by setting them to run at specific times, on a recurring schedule, or when certain events occur. This tool, integrated into Windows, helps streamline processes and ensures that repetitive tasks are performed consistently and efficiently.

**Steps**:

Step 1: Open Task Scheduler
- Press Windows Key + R, type taskschd.msc, and press Enter.
- This will launch the Task Scheduler interface.
  
Step 2: Create a New Task
- In the Task Scheduler window, click Action > Create Task.

Step 3: General Settings
- Under the General tab:
    - Name: Provide a name for your task (e.g., "Network Scanner Task").
    - Description: (Optional) Add a description for what this task does.
    - Security Options:
          - Select Run whether user is logged on or not to ensure it runs in the background.
          - Check Run with highest privileges if the script requires administrative rights.
<img width="1102" alt="Screenshot 2024-10-24 at 7 09 27 PM" src="https://github.com/user-attachments/assets/39f4e24d-b0d3-43e2-ba8d-5067d9fbee34">

      
Step 4: Set a Trigger
- Under the Triggers tab:
    - Click New.
    - Set a schedule based on how often you want the script to run (e.g., daily, weekly).
    - Choose the start time and other relevant options.
    - Click OK.
<img width="1113" alt="Screenshot 2024-10-24 at 7 11 13 PM" src="https://github.com/user-attachments/assets/78c32b02-56d3-4177-853b-af3540a9bb35">

      
Step 5: Add an Action to Run the Script
- Under the Actions tab:
    - Click New.
    - Action: Choose Start a Program.
    - Program/script: Enter powershell.exe.
    - Add arguments: Add the location of the PowerShell script you want to run.
    - This ensures that PowerShell bypasses the execution policy and runs the script without restriction.
    - Start in: Optionally, you can set the directory to where your scripts are stored.
<img width="1440" alt="Screenshot 2024-10-24 at 7 15 31 PM" src="https://github.com/user-attachments/assets/3d1bbb6e-93f0-47e4-a7bc-d367bceede4e">


Step 6: Conditions and Settings
- Under the Conditions tab:
    - You can specify when the task should run based on system conditions (e.g., idle, AC power, etc.).
    - Adjust these according to your preference.
- Under the Settings tab:
    - Check Allow task to be run on demand if you want to be able to manually trigger the task.
    - You may also want to enable If the task fails, restart every... to ensure the task reruns if it fails.
<img width="1112" alt="Screenshot 2024-10-24 at 7 17 35 PM" src="https://github.com/user-attachments/assets/ac502eac-ec81-4718-9878-a86176267a33">


Step 7: Review and Save
- Review all the settings, then click OK.
- If prompted, enter your administrative credentials to save the task.
<img width="1112" alt="Screenshot 2024-10-24 at 7 18 39 PM" src="https://github.com/user-attachments/assets/54a0b335-9277-46c4-b20d-5ab8c4ca5439">


Step 8: Test the Task
- After saving the task, right-click on the task name in Task Scheduler and select Run to manually trigger the network scan.
- You can check the results in the location where you have programmed the script to log the output.

  
## Conclusion:
This project highlights the powerful role PowerShell can play in automating cybersecurity tasks. The developed scripts are capable of monitoring key system and network activities, detecting vulnerabilities, and responding to potential threats. Each script can be further customized based on the environment's unique security requirements. The combination of these automated scripts provides a robust foundation for real-time monitoring and threat detection, ultimately improving the overall security posture of any organization.

The custom toolkits are ready for real-world use, and they demonstrate the effectiveness of PowerShell in a cybersecurity context.

By using PowerShell, these solutions can be implemented quickly and efficiently, making it a valuable tool for any cybersecurity professional.


