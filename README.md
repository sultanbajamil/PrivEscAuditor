# 🛡️ PrivEscAuditor

A modular, cross-platform local privilege escalation auditing tool written in pure Python with **zero external dependencies**. It helps security administrators and Red Teams audit local system configurations for security weaknesses that could lead to privilege escalation. 

At the end of the scan, it generates a comprehensive, responsive **HTML report** (using Tailwind CSS) and a raw **JSON data file** for SIEM integration or automation pipelines.

---

## 🚀 Features

- **Cross-Platform**: Automatically detects the host OS (Windows or Linux) and executes platform-specific checks.
- **Zero Dependencies**: Relies entirely on the Python Standard Library (e.g., `winreg`, `ctypes`, `subprocess`, `json`, `platform`), ensuring it can run in highly locked-down or isolated corporate environments.
- **Extensible Architecture**: Adding new checks is as simple as creating a subclass of `BaseCheck` and placing it in the platform directory.
- **Detailed Reporting**: Generates a professional, interactive HTML report with clear severity levels (Critical, High, Medium, Low, Info) and remediation recommendations.

---

## 📁 Project Structure

```
PrivEscAuditor/
│
├── main.py                     # CLI Entry point
├── README.md                   # Project documentation
│
├── core/
│   ├── base_check.py           # Abstract Base Class and CheckResult structures
│   ├── engine.py               # Platform detection & orchestration engine
│   └── reporter.py             # HTML and JSON report generator
│
└── checks/
    ├── windows/                # Windows-specific privilege escalation audits
    │   ├── always_install_elevated.py
    │   ├── unquoted_service_paths.py
    │   ├── token_privileges.py
    │   ├── writable_path_dirs.py
    │   └── unattended_files.py
    │
    └── linux/                  # Linux-specific privilege escalation audits
        ├── suid_files.py
        ├── writable_etc.py
        ├── sudo_rights.py
        └── writable_path_dirs.py
```

---

## 🔍 Auditing Capabilities

### 🪟 Windows Audits
1. **AlwaysInstallElevated Registry**: Checks if the policies that allow non-admin users to install MSI files with system privileges are enabled.
2. **Unquoted Service Paths**: Queries service executables with spaces in their path that lack quotation marks, and checks if the current user has write access to any of the parent folders.
3. **Token Privileges**: Checks the current process token for highly dangerous user privileges (e.g., `SeImpersonatePrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege`).
4. **Writable PATH Directories**: Evaluates system environmental variables (`%PATH%`) to locate custom directories writable by the current user (which can lead to DLL Hijacking).
5. **Unattended Setup Files**: Searches for leftover `Unattend.xml` or setup files containing plaintext or Base64 deployment credentials.

### 🐧 Linux Audits
1. **SUID/SGID Binaries**: Scans binary directories to find files with SUID/SGID bits set, automatically correlating them with dangerous GTFOBins (e.g., SUID `find`, `python`, `bash`).
2. **Writable `/etc` Configs**: Verifies if sensitive files like `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, or `/etc/exports` are writable by the executing user.
3. **Sudo Privileges (NOPASSWD)**: Audits sudo permissions non-interactively to check if the current user can execute commands as root without a password.
4. **Writable PATH Directories**: Scans the path directories to find folders where the user has write rights.

---

## 🛠️ How to Run

Since the tool requires no third-party packages, you can execute it immediately using a standard Python 3 interpreter:

```bash
# Run a basic scan (generates report.html and report.json in current directory)
python main.py

# Specify custom paths for HTML and JSON outputs
python main.py --html C:\Users\Public\audit_report.html --json C:\Users\Public\audit.json

# Run with verbose logging for debugging
python main.py --verbose
```

---

## 🌐 Web User Interface

To run the auditor through a visual dashboard in your browser, you can launch the local web server:

1. **Install Flask** (the only optional dependency for the Web UI):
   ```bash
   pip install flask
   ```

2. **Run the web application**:
   ```bash
   python web_app.py
   ```

3. Open your browser and navigate to `http://127.0.0.1:5000`.

From the dashboard, you can trigger new system scans, inspect triggered vulnerabilities with severity-colored badges, and read specific remediation guidelines.

---

## ⚙️ Adding Custom Checks

The framework is designed for easy expansion. To add a new check:

1. Create a Python file in `checks/windows/` or `checks/linux/` (e.g., `checks/windows/my_new_check.py`).
2. Inherit from `BaseCheck` and implement the abstract properties and methods:

```python
from core.base_check import BaseCheck, CheckResult

class MyNewCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Example Configuration Audit"

    @property
    def description(self) -> str:
        return "Checks a specific setting."

    @property
    def category(self) -> str:
        return "Registry" # or Filesystem, Services, etc.

    @property
    def severity(self) -> str:
        return "Medium"

    def run(self) -> CheckResult:
        # Perform audit logic here...
        triggered = True 
        findings = ["Found misconfiguration in key X"]
        
        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings,
            recommendation="Change key X to value Y."
        )
```

3. Import and append your check class to the `self.checks` list inside `core/engine.py`.

---

## 🛡️ Disclaimer
This tool is intended for defensive security auditing, posture management, and authorized penetration testing. Do not run this tool against systems where you do not have explicit authorization.
