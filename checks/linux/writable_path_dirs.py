import os
from core.base_check import BaseCheck, CheckResult

class WritablePathDirsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Writable PATH Directories Check"

    @property
    def description(self) -> str:
        return "Checks if any directory in the current user's PATH environment variable is writable. Writable directories in the PATH can allow attackers to hijack commands or drop malicious executable scripts/binaries."

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
        recommendation = "Review the directories listed in the user's PATH environment variable. Remove write access for standard users from any folder in the PATH, especially if it precedes system directories like /bin or /usr/bin."

        path_env = os.environ.get("PATH", "")
        if not path_env:
            return CheckResult(
                check_name=self.name,
                category=self.category,
                severity="Info",
                triggered=False,
                details=["PATH environment variable is empty or not accessible."],
                recommendation=""
            )

        # Split Linux PATH by colon
        paths = [p.strip() for p in path_env.split(":") if p.strip()]
        
        for path in paths:
            # Check if directory exists and is writable
            if os.path.isdir(path) and self.is_writable(path):
                triggered = True
                findings.append(f"Writable PATH Directory: {path}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Info",
            triggered=triggered,
            details=findings if findings else ["All directories in the system PATH are secure (not writable by current user)."],
            recommendation=recommendation if triggered else ""
        )
