import winreg
from core.base_check import BaseCheck, CheckResult

class AlwaysInstallElevatedCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "AlwaysInstallElevated Registry Key Check"

    @property
    def description(self) -> str:
        return "Checks if AlwaysInstallElevated is enabled in both HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER registry paths. If enabled, any user can run installations with elevated system privileges."

    @property
    def category(self) -> str:
        return "Registry"

    @property
    def severity(self) -> str:
        return "High"

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Disable AlwaysInstallElevated by setting the registry value to 0 or deleting the registry values from HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer and HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer."

        keys_to_check = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\Installer")
        ]

        hklm_enabled = False
        hkcu_enabled = False

        for hkey, subkey in keys_to_check:
            try:
                key = winreg.OpenKey(hkey, subkey)
                value, regtype = winreg.QueryValueEx(key, "AlwaysInstallElevated")
                winreg.CloseKey(key)
                if value == 1:
                    findings.append(f"AlwaysInstallElevated is enabled (value: 1) in {'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{subkey}")
                    if hkey == winreg.HKEY_LOCAL_MACHINE:
                        hklm_enabled = True
                    else:
                        hkcu_enabled = True
            except FileNotFoundError:
                # Key or value doesn't exist, which is secure
                pass
            except Exception as e:
                findings.append(f"Error checking registry: {str(e)}")

        # Both must be set for AlwaysInstallElevated to be exploitable, but either is a risk
        if hklm_enabled and hkcu_enabled:
            triggered = True
            self.severity_level = "High"
        elif hklm_enabled or hkcu_enabled:
            triggered = True
            findings.append("Note: AlwaysInstallElevated is set on one registry hive only. Typically both HKLM and HKCU settings must be active to be fully exploitable, but this remains a major misconfiguration.")
            self.severity_level = "Medium"

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings if findings else ["AlwaysInstallElevated registry keys are not set (Default/Secure)."],
            recommendation=recommendation if triggered else ""
        )
