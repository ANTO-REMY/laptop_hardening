# Windows Laptop Hardening

This repository provides a PowerShell script to safely harden Windows 10/11 laptops. The script automates basic security and health checks: Windows Update, Firewall, Defender, running services, open ports, tool installation, and BitLocker status guidance. All actions are auditable and logs are saved to the `reports/` folder.

**Usage Example:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows-harden.ps1 -DryRun             # Simulate actions, no changes
.\windows-harden.ps1 -LogPath .\reports  # Run and save evidence
```

**Main Features:**
- Checks and reports Windows health & security
- Enables critical protections (with confirmation)
- Never auto-encrypts, deletes files, or reboots
- Logs and evidence files for every run (`reports/`)

**Recommended:**  
Test in a virtual machine; review logs before sharing.
