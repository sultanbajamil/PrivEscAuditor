import os
from core.base_check import BaseCheck, CheckResult

class UnattendedFilesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Unattended Installation Files Check"

    @property
    def description(self) -> str:
        return "Searches for unattended setup configuration files (e.g. Unattend.xml) left on the filesystem. These files are used during automated deployments and often contain plaintext or Base64-encoded administrative passwords."

    @property
    def category(self) -> str:
        return "Filesystem"

    @property
    def severity(self) -> str:
        return "High"

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Remove unattended install configuration files (Unattend.xml, Unattended.xml, sysprep.xml) from system deployment paths once installation is complete, or scrub any sensitive credential tags from them."

        # Common locations for Unattended files
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        potential_paths = [
            os.path.join(system_root, "Panther", "Unattend.xml"),
            os.path.join(system_root, "Panther", "Unattended.xml"),
            os.path.join(system_root, "Panther", "Unattend", "Unattend.xml"),
            os.path.join(system_root, "Panther", "Unattend", "Unattended.xml"),
            os.path.join(system_root, "System32", "Sysprep", "unattend.xml"),
            os.path.join(system_root, "System32", "Sysprep", "Panther", "unattend.xml"),
            os.path.join(system_root, "sysprep.inf"),
            os.path.join(system_root, "system32", "sysprep.inf")
        ]

        for path in potential_paths:
            if os.path.exists(path):
                # Check if it is readable by the current user
                try:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read(500) # Read the beginning to see if we can open it
                    
                    # File exists and is readable
                    triggered = True
                    # Let's check if we find "password" in the content as an indicator
                    has_password = "password" in content.lower() or "credentials" in content.lower()
                    findings.append(
                        f"Readable Unattended File Found: {path} "
                        f"(Contains potential password fields: {'Yes' if has_password else 'Unknown/Not found in first 500 bytes'})"
                    )
                except PermissionError:
                    # File exists but current user cannot read it (this is relatively safe)
                    findings.append(f"Unattended File Found but Access Denied (Secure): {path}")
                except Exception as e:
                    findings.append(f"Found {path} but error reading: {str(e)}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings if findings else ["No unattended installation files found."],
            recommendation=recommendation if triggered else ""
        )
