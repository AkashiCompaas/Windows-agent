param (
    [string]$wazuhManagerIP = "10.10.0.90",
    [string]$wazuhAgentGroup = "Windows",
    [string]$wazuhAgentName = "Windows-Machine"
)

# Define URLs and Paths
$sysmonScriptUrl = "https://raw.githubusercontent.com/CyberOpsLab/Windows_Sysmon/main/sysmon_install.ps1"
$sysmonConfigUrl = "https://raw.githubusercontent.com/CyberOpsLab/sysmon-config/master/sysmonconfig-export.xml"
$wazuhInstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi"
$sysmonConfigWazuhUrl = "https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml"
$ossecConfUrl = "https://raw.githubusercontent.com/CyberOpsLab/Windows-agent/main/ossec.conf"
$yaraInstallerUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"
$yaraRulesPyUrl = "https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/download_yara_rules.py"
$yaraBatchUrl = "https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/yara.bat"
$yaraRulesUrl = "https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/yara_rules.yar"

# Active-Response Directory and GitHub Source
$activeResponseDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\"
$activeResponseRawBase = "https://raw.githubusercontent.com/CyberOpsLab/Windows-agent/main/active-response/"

# Set Local Paths
$sysmonFolder = "C:\Sysmon"
$wazuhInstallerPath = "$env:TEMP\wazuh-agent.msi"
$ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$yaraZipPath = "$env:TEMP\yara-v4.5.2-2326-win64.zip"
$yaraExtractedPath = "$env:TEMP\yara-v4.5.2-2326-win64"
$yaraInstallPath = "$activeResponseDir\yara"
$yaraRulesPath = "$yaraInstallPath\rules"

# Create required directories
New-Item -ItemType Directory -Path $sysmonFolder -Force | Out-Null
New-Item -ItemType Directory -Path $yaraInstallPath -Force | Out-Null
New-Item -ItemType Directory -Path $yaraRulesPath -Force | Out-Null
New-Item -ItemType Directory -Path $activeResponseDir -Force | Out-Null

# Download Sysmon Install Script & Configuration
Invoke-WebRequest -Uri $sysmonScriptUrl -OutFile "$env:TEMP\sysmon_install.ps1"
Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile "$sysmonFolder\sysmonconfig.xml"

# Install Python dependencies and PIP
$pythonVersion = "3.13.2"; $pythonInstaller = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-amd64.exe"; $packages = "requests", "numpy", "pandas"; if (-not (Get-Command python -ErrorAction SilentlyContinue)) {Invoke-WebRequest -Uri $pythonInstaller -OutFile "python-installer.exe"; Start-Process -FilePath ".\python-installer.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait; Remove-Item -Path ".\python-installer.exe"}; python -m pip install --upgrade pip; python -m pip install $packages

# Run Sysmon Installation
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$env:TEMP\sysmon_install.ps1`"" -Wait -NoNewWindow

# Apply Sysmon Configuration
Start-Process -FilePath "$sysmonFolder\Sysmon64.exe" -ArgumentList "-accepteula -i sysmonconfig.xml" -Wait -NoNewWindow

# Download & Install Wazuh Agent
Invoke-WebRequest -Uri $wazuhInstallerUrl -OutFile $wazuhInstallerPath
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$wazuhInstallerPath`" /q WAZUH_MANAGER=$wazuhManagerIP WAZUH_AGENT_GROUP=$wazuhAgentGroup WAZUH_AGENT_NAME=$wazuhAgentName" -Wait -NoNewWindow

# Download and Replace ossec.conf
Invoke-WebRequest -Uri $ossecConfUrl -OutFile $ossecConfPath

# Start Wazuh Agent Service
Start-Service -Name "WazuhSvc"

# Restart Wazuh Agent to Apply Configuration Changes
Restart-Service -Name wazuh

# Download & Install YARA
Invoke-WebRequest -Uri $yaraInstallerUrl -OutFile $yaraZipPath
Expand-Archive -Path $yaraZipPath -DestinationPath $yaraExtractedPath -Force
Copy-Item "$yaraExtractedPath\yara64.exe" -Destination $yaraInstallPath -Force

# Install Python & Dependencies for YARA
if (-Not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Install Python 3.13.0 manually."
    exit 1
}
pip install valhallaAPI

# Download YARA Configuration Files
Invoke-WebRequest -Uri $yaraRulesPyUrl -OutFile "$env:TEMP\download_yara_rules.py"
Invoke-WebRequest -Uri $yaraBatchUrl -OutFile "$activeResponseDir\yara.bat"
Invoke-WebRequest -Uri $yaraRulesUrl -OutFile "$yaraRulesPath\yara_rules.yar"

# Execute Python Script to Download YARA Rules
python "$env:TEMP\download_yara_rules.py"
Copy-Item "$env:TEMP\yara_rules.yar" -Destination "$yaraRulesPath\yara_rules.yar" -Force

# Download and Install Active-Response Scripts
$activeResponseFiles = @("remove-threat.py")
foreach ($file in $activeResponseFiles) {
    Invoke-WebRequest -Uri "$activeResponseRawBase$file" -OutFile "$activeResponseDir$file"
}

# Set Execution Permissions for Active Response Scripts
foreach ($file in $activeResponseFiles) {
    icacls "$activeResponseDir$file" /grant Everyone:F /T /C | Out-Null
}

# Restart Wazuh Agent to Apply All Changes
Restart-Service -Name wazuh
