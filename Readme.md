# Sysmon, Wazuh EDR, and YARA Installation Script

This PowerShell script automates the installation and configuration of **Sysmon, Wazuh EDR Agent, and YARA** on a Windows machine. It also downloads and sets up Active-Response scripts.

---

## 📌 Features
- **Installs and Configures Sysmon** for event logging.
- **Installs Wazuh EDR Agent** with configurable parameters.
- **Downloads and installs YARA** with malware detection rules.
- **Downloads and sets up Active-Response scripts** for automated threat response.

---

## 📂 Modules Installed
The script performs the following installations:

| Module            | Description |
|------------------|-------------|
| **Sysmon**      | Logs system activity for security analysis. |
| **Wazuh EDR**   | Endpoint Detection and Response agent. |
| **YARA**        | Malware classification and detection tool. |
| **Active-Response** | Security response automation scripts. |

---

## 🚀 Installation Guide

### **Step 1: Run PowerShell as Administrator**
1. Click **Start**, search for `PowerShell`, **right-click** and select **Run as Administrator**.

### **Step 2: Download and Run the Script**
#### ✅ **Run with Default Values**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install_sysmon_wazuh_yara.ps1
```
---------------------------------------------------------------------
## 📝 How to Add More Files to Active-Response

If you need to add more files to the **Active-Response directory**, follow these steps:

### **Step 1: Open the Script in a Text Editor**
Edit the PowerShell script (`install_sysmon_wazuh_yara.ps1`) and locate this section:

```powershell
$activeResponseFiles = @(
    "remove-threat.py",
    "another-script.bat",
    "some-config.json"
)
