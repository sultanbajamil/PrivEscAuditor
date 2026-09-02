import os
from core.base_check import BaseCheck, CheckResult

class WritablePathDirsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Writable PATH Directories Check"

    @property
    def description(self) -> str:
        return "Scans directories listed in the system PATH environment variable to check if any of them are writable by the current user. Writable PATH directories allow DLL hijacking or binary planting."

    @property
    def category(self) -> str:
        return "Filesystem"

    @property
    def severity(self) -> str:
        return "High"

    def is_writable(self, directory: str) -> bool:
        """Tests if a directory is writable by attempting to write a temp file."""
        if not os.path.isdir(directory):
            return False
        try:
            temp_file_path = os.path.join(directory, ".priv_esc_path_temp")
            with open(temp_file_path, "w") as f:
                f.write("test")
            os.remove(temp_file_path)
            return True
        except:
            return False

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Remove write permissions for standard/non-privileged users from any custom folders added to the system PATH. Ensure system PATH contains only secure, administrator-only write-accessible directories."

        path_env = ""
        # Try to query ONLY the System PATH from Registry (to avoid User PATH false positives)
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\Environment")
            path_env, _ = winreg.QueryValueEx(key, "Path")
            winreg.CloseKey(key)
        except Exception as e:
            # Fallback to combined environment PATH but we will filter out user profile directories
            path_env = os.environ.get("PATH", "")

        if not path_env:
            return CheckResult(
                check_name=self.name,
                category=self.category,
                severity="Info",
                triggered=False,
                details=["System PATH environment variable is empty or not accessible."],
                recommendation=""
            )

        # Get user profile directory to filter out user profile paths (safe from PrivEsc)
        user_profile = os.environ.get("USERPROFILE", "").lower()

        # Split Windows PATH by semicolon
        paths = [p.strip() for p in path_env.split(";") if p.strip()]
        
        for path in paths:
            # Expand environment variables in path (e.g. %SystemRoot%)
            expanded_path = os.path.expandvars(path)
            
            # Filter out user profile directories
            if user_profile and expanded_path.lower().startswith(user_profile):
                continue
                
            if not os.path.isdir(expanded_path):
                continue
            
            # Check if writable
            if self.is_writable(expanded_path):
                triggered = True
                findings.append(f"Writable SYSTEM PATH Directory: {expanded_path}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings if findings else ["All directories in the system PATH are secure (not writable by current user)."],
            recommendation=recommendation if triggered else ""
        )

