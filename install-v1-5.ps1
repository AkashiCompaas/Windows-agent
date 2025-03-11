param (
    [string]$wazuhManagerIP = "10.10.0.90",    # Changeable Wazuh Manager IP
    [string]$wazuhAgentGroup = "Windows-Demo", # Changeable Wazuh Agent Group
    [string]$wazuhAgentName = "Hello"          # Changeable Wazuh Agent Name
)

# Step 1: Check if Python 3 is installed
Write-Output "Checking if Python is installed..."

if (-Not (Get-Command python3 -ErrorAction SilentlyContinue)) {
    Write-Output "Python 3 is not installed. Installing Python 3..."

    # Step 2: Download Python 3.10 installer
    $pythonInstallerUrl = "https://www.python.org/ftp/python/3.10.4/python-3.10.4-amd64.exe"
    $pythonInstallerPath = "$env:TEMP\python-installer.exe"

    # Download the Python installer
    Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $pythonInstallerPath

    # Step 3: Install Python silently and ensure "Add Python to PATH" is enabled
    Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait -NoNewWindow

    # Step 4: Verify Python installation
    if (-Not (Get-Command python3 -ErrorAction SilentlyContinue)) {
        Write-Host "Python installation failed. Exiting..."
        exit 1
    }

    Write-Output "Python 3 installed successfully."
}

# Step 5: Ensure pip is installed and working
Write-Output "Ensuring pip is installed for Python..."
python -m ensurepip --upgrade

# Install required Python packages (if needed)
Write-Output "Installing Python dependencies..."
pip install --upgrade pip
pip install valhallaAPI

# Define URLs for required downloads
$sysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonFolder = "C:\Sysmon"                  # Sysmon directory path
$sysmonZipPath = "$env:TEMP\Sysmon.zip"      # Path to store downloaded zip file

# Ensure Sysmon folder exists with correct permissions
Write-Output "Ensuring Sysmon directory exists..."
New-Item -ItemType Directory -Path $sysmonFolder -Force | Out-Null

# Download Sysmon ZIP file
Write-Output "Downloading Sysmon..."
Invoke-WebRequest -Uri $sysmonZipUrl -OutFile $sysmonZipPath

# Check if the Sysmon zip file was downloaded successfully
if (-Not (Test-Path $sysmonZipPath)) {
    Write-Host "Sysmon ZIP file download failed. Please check the network connection."
    exit 1
}

# Unzip Sysmon to the C:\Sysmon folder
Write-Output "Extracting Sysmon files..."
Expand-Archive -Path $sysmonZipPath -DestinationPath $sysmonFolder -Force

# Verify that Sysmon executable exists after extraction
$sysmonExecutablePath = "$sysmonFolder\Sysmon64.exe"
if (-Not (Test-Path $sysmonExecutablePath)) {
    Write-Host "Sysmon64.exe not found. Please check the extraction process."
    exit 1
}

Write-Output "Sysmon installation extracted to C:\Sysmon."

# Run Sysmon installation (using extracted executable)
Write-Output "Running Sysmon installation..."
Start-Process -FilePath $sysmonExecutablePath -ArgumentList "-accepteula -i $sysmonFolder\sysmonconfig.xml" -Wait -NoNewWindow

Write-Output "Sysmon installed and configured successfully."

# Define paths for YARA installation and rules
$yaraZipPath = "$env:TEMP\yara-v4.5.2-2326-win64.zip"
$yaraExtractedPath = "$env:TEMP\yara-v4.5.2-2326-win64"
$yarafolder = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$yaraInstallPath = "$yarafolder\yara"
$yaraRulesPath = "$yaraInstallPath\rules"

# Download and Install YARA
Write-Output "Downloading and installing YARA..."
Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" -OutFile $yaraZipPath
Expand-Archive -Path $yaraZipPath -DestinationPath $yaraExtractedPath -Force
Copy-Item "$yaraExtractedPath\yara64.exe" -Destination $yaraInstallPath -Force

# Install YARA rules
Write-Output "Downloading YARA rules..."
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/yara_rules.yar" -OutFile "$yaraRulesPath\yara_rules.yar"

# Define Wazuh installer URL and local path
$wazuhInstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi"
$wazuhInstallerPath = "$env:TEMP\wazuh-agent.msi"

# Download Wazuh agent
Write-Output "Downloading Wazuh Agent..."
Invoke-WebRequest -Uri $wazuhInstallerUrl -OutFile $wazuhInstallerPath

# Install Wazuh Agent (EDR Agent)
Write-Output "Installing EDR Agent (Wazuh)..."
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$wazuhInstallerPath`" /q WAZUH_MANAGER=$wazuhManagerIP WAZUH_AGENT_GROUP=$wazuhAgentGroup WAZUH_AGENT_NAME=$wazuhAgentName" -Wait -NoNewWindow

# Download and Replace ossec.conf
$ossecConfUrl = "https://raw.githubusercontent.com/CyberOpsLab/Windows-agent/main/ossec.conf"
$ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$newConfig = Invoke-WebRequest -Uri $ossecConfUrl -UseBasicPipelining | Select-Object -ExpandProperty Content

Write-Output "Downloading new Wazuh configuration block..."

# Check if the file exists
if (Test-Path $ossecConfPath) {
    # Append the new configuration block to the existing file
    Write-Output "Appending new configuration block to the existing ossec.conf..."
    Add-Content -Path $ossecConfPath -Value $newConfig
} else {
    Write-Output "ossec.conf file not found. Creating a new file with the configuration..."
    # If the file does not exist, create it and write the configuration block
    Set-Content -Path $ossecConfPath -Value $newConfig
}

Write-Output "Configuration updated successfully."

# Start Wazuh Agent Service
Write-Output "Starting EDR Agent Service..."
Start-Service -Name "WazuhSvc"

# Download and Install Active-Response Scripts
Write-Output "Downloading Active-Response scripts..."
$activeResponseFiles = @("remove-threat.py", "another-script.py", "example.bat")
$activeResponseRawBase = "https://raw.githubusercontent.com/CyberOpsLab/Windows-agent/main/active-response/"
$activeResponseDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\"

# Ensure Active-Response directory exists
New-Item -ItemType Directory -Path $activeResponseDir -Force | Out-Null

foreach ($file in $activeResponseFiles) {
    $fileUrl = "$activeResponseRawBase$file"
    $filePath = "$activeResponseDir$file"
    Write-Output "Downloading: $file"
    Invoke-WebRequest -Uri $fileUrl -OutFile $filePath
}

# Set Execution Permissions for Active Response Scripts
Write-Output "Setting execution permissions for Active-Response scripts..."
icacls "$activeResponseDir*" /grant Everyone:F /T /C | Out-Null

Write-Output "All Active-Response scripts downloaded and permissions set successfully!"

# Restart Wazuh Agent to Apply All Changes
Write-Output "Finalizing installation. Restarting EDR Agent..."
Restart-Service -Name wazuh

Write-Output "Installation and configuration complete!"
