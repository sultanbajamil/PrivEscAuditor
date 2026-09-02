import winreg
import os
import shlex
from core.base_check import BaseCheck, CheckResult

class UnquotedServicePathsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "Unquoted Service Paths Check"

    @property
    def description(self) -> str:
        return "Scans Windows services for executable paths that contain spaces and are not enclosed in quotes. An attacker with write access to parent directories could place a malicious executable to hijack the service execution."

    @property
    def category(self) -> str:
        return "Services"

    @property
    def severity(self) -> str:
        return "Medium"

    def is_writable(self, directory: str) -> bool:
        """Tests if a directory is writable by attempting to write a temp file."""
        if not os.path.isdir(directory):
            return False
        try:
            temp_file_path = os.path.join(directory, ".priv_esc_audit_temp")
            with open(temp_file_path, "w") as f:
                f.write("test")
            os.remove(temp_file_path)
            return True
        except:
            return False

    def parse_executable_path(self, image_path: str) -> str:
        """Extracts the actual executable path from service ImagePath."""
        image_path = image_path.strip()
        if not image_path:
            return ""
        
        # If it's already quoted, it's safe from unquoted path vulnerability
        if image_path.startswith('"'):
            return ""

        # Normalize slashes and resolve environment variables
        image_path = os.path.expandvars(image_path)

        # Handle arguments. Look for .exe and split there
        lower_path = image_path.lower()
        exe_index = lower_path.find(".exe")
        if exe_index != -1:
            return image_path[:exe_index + 4]

        # If no .exe, split by spaces but check if files exist (fallback)
        parts = shlex.split(image_path)
        if parts:
            return parts[0]
            
        return image_path

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Enclose the service ImagePath registry value in double quotes (e.g., change C:\\Program Files\\Sub\\Service.exe to \"C:\\Program Files\\Sub\\Service.exe\") via reg.exe or Service Control Manager."

        try:
            services_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
            i = 0
            while True:
                try:
                    service_name = winreg.EnumKey(services_key, i)
                    i += 1
                    
                    # Open service subkey
                    service_subkey = winreg.OpenKey(services_key, service_name)
                    try:
                        image_path, _ = winreg.QueryValueEx(service_subkey, "ImagePath")
                        winreg.CloseKey(service_subkey)
                        
                        # Process ImagePath
                        exec_path = self.parse_executable_path(image_path)
                        if exec_path and " " in exec_path:
                            # Verify if any parent directory is writable (actual privilege escalation risk)
                            # E.g., for C:\Program Files\Vendor Name\Service.exe
                            # Check C:\, C:\Program Files\, C:\Program Files\Vendor Name\
                            normalized_path = os.path.normpath(exec_path)
                            parts = normalized_path.split(os.sep)
                            
                            writable_parents = []
                            # Reconstruct paths step by step
                            for idx in range(1, len(parts)):
                                parent_dir = os.sep.join(parts[:idx])
                                if not parent_dir:
                                    continue
                                if ":" in parent_dir and len(parent_dir) <= 3:
                                    parent_dir += os.sep  # Handle drive letter root like C:\
                                
                                if self.is_writable(parent_dir):
                                    writable_parents.append(parent_dir)

                            if writable_parents:
                                triggered = True
                                findings.append(
                                    f"Service: {service_name} | ImagePath: {image_path} | "
                                    f"Writable Directories: {', '.join(writable_parents)}"
                                )
                            else:
                                # Still worth listing as a warning/low finding even if parent directory is not writable by current user (since other users/groups might write to it)
                                findings.append(
                                    f"[Potential] Service: {service_name} | ImagePath: {image_path} (No write access detected for current user on parent paths)"
                                )
                    except FileNotFoundError:
                        # ImagePath value not found (drivers/legacy services)
                        winreg.CloseKey(service_subkey)
                    except Exception:
                        winreg.CloseKey(service_subkey)
                except OSError:
                    # End of subkeys
                    break
            winreg.CloseKey(services_key)
        except Exception as e:
            findings.append(f"Error querying registry Services key: {str(e)}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity="High" if triggered else "Low" if findings else "Info",
            triggered=triggered or len(findings) > 0,
            details=findings if findings else ["No unquoted service paths detected."],
            recommendation=recommendation if (triggered or findings) else ""
        )
