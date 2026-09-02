import os
from core.base_check import BaseCheck, CheckResult

class WritableEtcCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Writable /etc/ Configuration Files Check"

    @property
    def description(self) -> str:
        return "Checks if critical system configuration files under /etc (like passwd, shadow, sudoers) are writable by the current unprivileged user. Write access to these files allows immediate privilege escalation to root."

    @property
    def category(self) -> str:
        return "Filesystem"

    @property
    def severity(self) -> str:
        return "Critical"

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Restore secure file permissions immediately: /etc/passwd should be 644, /etc/shadow should be 640 or 600 (owner: root:shadow or root:root), and /etc/sudoers should be 440 (owner: root:root)."

        files_to_check = {
            "/etc/passwd": "Allows adding new users or modifying existing user properties (e.g., changing root password hash).",
            "/etc/shadow": "Contains encrypted user passwords; being writable allows modifying passwords or hashes directly.",
            "/etc/sudoers": "Defines user sudo privileges; being writable allows granting root privileges to anyone.",
            "/etc/exports": "Controls NFS exports; being writable allows enabling insecure NFS shares with root_squash disabled."
        }

        for file_path, risk in files_to_check.items():
            if os.path.exists(file_path):
                # Check write permission
                if os.access(file_path, os.W_OK):
                    triggered = True
                    findings.append(f"🚨 Writable file: {file_path} - Risk: {risk}")
            else:
                # File doesn't exist (should not happen for passwd on Linux, but safe fallback)
                pass

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings if findings else ["All tested /etc configuration files are securely set to read-only."],
            recommendation=recommendation if triggered else ""
        )
