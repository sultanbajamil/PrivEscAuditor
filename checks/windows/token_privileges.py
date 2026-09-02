import subprocess
import os
from core.base_check import BaseCheck, CheckResult

class TokenPrivilegesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Process Token Privileges Check"

    @property
    def description(self) -> str:
        return "Checks the security privileges assigned to the current process token. Dangerous privileges like SeImpersonatePrivilege, SeDebugPrivilege, or SeBackupPrivilege can be leveraged for privilege escalation."

    @property
    def category(self) -> str:
        return "System Info"

    @property
    def severity(self) -> str:
        return "High"

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Review why the current user or process has these administrative privileges. Practice the Principle of Least Privilege (PoLP) and remove unnecessary privileges from user groups."

        # List of interesting/high-risk privileges
        dangerous_privileges = {
            "SeImpersonatePrivilege": "Allows impersonation of other tokens (vulnerable to Potato exploits if service account).",
            "SeDebugPrivilege": "Allows debugging other processes. Can read LSASS memory or inject code into SYSTEM processes.",
            "SeBackupPrivilege": "Allows backing up any file. Can read registry hives (SAM/SYSTEM) to dump local passwords.",
            "SeRestorePrivilege": "Allows restoring any file. Can overwrite system files or service executables.",
            "SeTakeOwnershipPrivilege": "Allows taking ownership of files or objects to modify their access controls.",
            "SeLoadDriverPrivilege": "Allows loading/unloading device drivers. Can be abused to load vulnerable drivers (BYOVD).",
            "SeTcbPrivilege": "Act as part of the operating system. Full access.",
            "SeAssignPrimaryTokenPrivilege": "Allows replacing a process-level token to execute code as another user."
        }

        try:
            # Run whoami /priv
            result = subprocess.run(["whoami", "/priv"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines:
                    # Clean up double spaces to parse columns
                    parts = [p.strip() for p in line.split("  ") if p.strip()]
                    if len(parts) >= 2:
                        priv_name = parts[0]
                        # Check if it's one of the dangerous ones
                        if priv_name in dangerous_privileges:
                            status = parts[-1]  # Typically Enabled or Disabled
                            triggered = True
                            findings.append(f"{priv_name}: Status={status} - Description: {dangerous_privileges[priv_name]}")
            else:
                findings.append(f"Could not run 'whoami /priv': {result.stderr}")
        except Exception as e:
            findings.append(f"Error checking token privileges: {str(e)}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings if findings else ["No high-risk token privileges detected for the current process."],
            recommendation=recommendation if triggered else ""
        )
