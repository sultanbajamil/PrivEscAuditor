import platform
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class AuditEngine:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.checks = []

    def load_checks(self):
        """Loads checks based on the detected operating system."""
        if self.os_type == "windows":
            logging.info("Windows system detected. Loading Windows audit checks...")
            try:
                from checks.windows.always_install_elevated import AlwaysInstallElevatedCheck
                from checks.windows.unquoted_service_paths import UnquotedServicePathsCheck
                from checks.windows.token_privileges import TokenPrivilegesCheck
                from checks.windows.writable_path_dirs import WritablePathDirsCheck
                from checks.windows.unattended_files import UnattendedFilesCheck
                
                self.checks = [
                    AlwaysInstallElevatedCheck(),
                    UnquotedServicePathsCheck(),
                    TokenPrivilegesCheck(),
                    WritablePathDirsCheck(),
                    UnattendedFilesCheck(),
                ]
            except ImportError as e:
                logging.error(f"Failed to load Windows checks: {e}")
                
        elif self.os_type == "linux":
            logging.info("Linux system detected. Loading Linux audit checks...")
            try:
                from checks.linux.suid_files import SuidFilesCheck
                from checks.linux.writable_etc import WritableEtcCheck
                from checks.linux.sudo_rights import SudoRightsCheck
                from checks.linux.writable_path_dirs import WritablePathDirsCheck
                
                self.checks = [
                    SuidFilesCheck(),
                    WritableEtcCheck(),
                    SudoRightsCheck(),
                    WritablePathDirsCheck(),
                ]
            except ImportError as e:
                logging.error(f"Failed to load Linux checks: {e}")
        else:
            logging.warning(f"Unsupported operating system: {self.os_type}")

    def run_all(self):
        """Executes all loaded checks and returns the results."""
        results = []
        logging.info(f"Running {len(self.checks)} checks...")
        for check in self.checks:
            logging.info(f"Running check: {check.name}")
            try:
                result = check.run()
                result.description = check.description
                results.append(result)
            except Exception as e:
                logging.error(f"Error running check {check.name}: {e}")
                # Create a failure result
                from core.base_check import CheckResult
                results.append(CheckResult(
                    check_name=check.name,
                    category=check.category,
                    severity=check.severity,
                    triggered=False,
                    details=[f"Error during execution: {str(e)}"],
                    recommendation="Review tool log outputs for errors.",
                    description=check.description
                ))
        return results
