import subprocess
from core.base_check import BaseCheck, CheckResult

class SudoRightsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Sudo Rights Check (NOPASSWD)"

    @property
    def description(self) -> str:
        return "Runs non-interactive sudo listing ('sudo -l -n') to verify if the current user can execute commands as root or another user without entering a password (NOPASSWD)."

    @property
    def category(self) -> str:
        return "System Info"

    @property
    def severity(self) -> str:
        return "High"

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Modify the /etc/sudoers file using 'visudo' to remove or restrict NOPASSWD privileges. Implement the principle of least privilege, requiring password authentication for administrative tasks."

        try:
            # Run sudo -l -n (non-interactive, will fail if password is required)
            result = subprocess.run(["sudo", "-l", "-n"], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines:
                    line = line.strip()
                    if "NOPASSWD:" in line:
                        triggered = True
                        findings.append(f"Sudo configuration allows passwordless execution: {line}")
                    elif "ALL" in line and not "NOPASSWD" in line:
                        # User has sudo rights but might need a password
                        findings.append(f"User has sudo rights (password may be required): {line}")
            else:
                # Sudo requires a password or user is not in sudoers
                # Output might look like "sudo: a password is required"
                err = result.stderr.strip() if result.stderr else "Sudo requires authentication or user has no sudo rights."
                findings.append(f"Sudo check completed: {err} (Secure default)")
                
        except FileNotFoundError:
            # sudo is not installed/present (e.g. minimal container environment)
            findings.append("Sudo binary not found on the system.")
        except Exception as e:
            findings.append(f"Error checking sudo rights: {str(e)}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity="Critical" if triggered and "ALL" in "".join(findings) else self.severity if triggered else "Info",
            triggered=triggered,
            details=findings,
            recommendation=recommendation if triggered else ""
        )
