# 🛡️ PrivEscAuditor: Local Privilege Escalation Auditing Framework

**PrivEscAuditor** is a modular, cross-platform local privilege escalation auditing tool written in pure Python with **zero external dependencies** for core scanning. It helps security analysts, system administrators, and Red Teams inspect local system configurations for security weaknesses that could enable unprivileged users to elevate privileges.

After completion, it produces a self-contained, responsive **HTML report** (styled with Tailwind CSS) and an exportable **JSON data file** for SIEM ingestion or automated CI/CD pipelines.

---

## 🏗️ Architecture

```text
PrivEscAuditor/
├── main.py                     # CLI Entry point
├── web_app.py                  # Flask Web Dashboard
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
1. **AlwaysInstallElevated Registry**:
   - Inspects both `HKCU` and `HKLM` policies to determine if non-administrative users can install MSI packages with elevated `NT AUTHORITY\SYSTEM` privileges.
2. **Unquoted Service Paths**:
   - Scans registered Windows services whose binary paths contain spaces and lack proper quotation marks, evaluating whether current user permissions permit binary planting.
3. **Token Privileges**:
   - Queries the current process access token for high-risk privileges commonly abused for local privilege escalation (e.g., `SeImpersonatePrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`).
4. **Writable PATH Directories**:
   - Audits all directories listed in the `%PATH%` environment variable to detect world-writable directories susceptible to DLL hijacking or search order abuse.
5. **Unattended Setup Files**:
   - Scans standard system locations for leftover installation files (`Unattend.xml`, `sysprep.inf`) containing plaintext or Base64 deployment credentials.

### 🐧 Linux Audits
1. **SUID / SGID Binaries**:
   - Identifies executables with the SUID/SGID bit set and cross-references them against known GTFOBins exploitation vectors.
2. **Writable Sensitive Configurations**:
   - Checks write permissions on critical system configuration files, such as `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, and `/etc/exports`.
3. **Sudo Privileges (NOPASSWD)**:
   - Audits sudo configurations non-interactively to detect entries granting passwordless root command execution.
4. **Writable System PATH Directories**:
   - Inspects directories in `$PATH` to identify locations where low-privileged users can plant malicious binaries.

---

## 🚀 Installation & Running

### Prerequisites
- Python 3.8 or higher.
- Zero third-party dependencies are required for standard CLI scans.
- *(Optional)* `Flask` is required only if you wish to run the Web GUI.

### Option 1: Command Line Interface (CLI)
Run a direct scan using standard Python:
```bash
# Standard scan (generates report.html and report.json)
python main.py

# Specify custom output locations
python main.py --html custom_report.html --json custom_report.json

# Enable verbose console debugging
python main.py --verbose
```

### Option 2: Interactive Web Dashboard
1. Install Flask:
   ```bash
   pip install flask
   ```
2. Launch the web application:
   ```bash
   python web_app.py
   ```
3. Open your browser to: **`http://127.0.0.1:5000`**
   - Trigger on-demand system scans.
   - Inspect findings grouped by severity (Critical, High, Medium, Low, Info).
   - View detailed remediation instructions for each discovered misconfiguration.

---

## ⚠️ Disclaimer
PrivEscAuditor is built strictly for authorized auditing, system hardening, and defensive training. Always ensure you have authorization before evaluating security controls on any host.
