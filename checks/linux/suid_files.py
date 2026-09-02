import os
import stat
from core.base_check import BaseCheck, CheckResult

class SuidFilesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "SUID/SGID Files Check"

    @property
    def description(self) -> str:
        return "Scans common executable paths for files with the SUID (Set Owner User ID) or SGID (Set Group User ID) flag set. If an administrative binary has SUID set, it runs with root permissions and might be abusable (GTFOBins)."

    @property
    def category(self) -> str:
        return "Filesystem"

    @property
    def severity(self) -> str:
        return "High"

    def run(self) -> CheckResult:
        triggered = False
        findings = []
        recommendation = "Remove the SUID/SGID bit (using chmod -s /path/to/binary) from any non-standard binaries or binaries that are listed in GTFOBins unless absolutely necessary for system operation."

        # Classic GTFOBins that are highly dangerous if SUID is enabled
        gtfo_bins = {
            "bash", "sh", "python", "python3", "perl", "ruby", "find", "nmap", 
            "vim", "vi", "nano", "less", "more", "awk", "sed", "env", "nc", 
            "netcat", "socat", "tar", "zip", "strace", "gdb", "cp", "mv", "dd"
        }

        search_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]
        
        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            
            try:
                for entry in os.scandir(search_dir):
                    if entry.is_file(follow_symlinks=False):
                        try:
                            file_stat = entry.stat()
                            mode = file_stat.st_mode
                            
                            # Check SUID (0o4000) or SGID (0o2000)
                            is_suid = bool(mode & stat.S_ISUID)
                            is_sgid = bool(mode & stat.S_ISGID)
                            
                            if is_suid or is_sgid:
                                binary_name = entry.name.lower()
                                flag_type = "SUID" if is_suid else "SGID"
                                if is_suid and is_sgid:
                                    flag_type = "SUID/SGID"
                                
                                # Check if it's a known dangerous binary
                                is_gtfo = binary_name in gtfo_bins
                                if is_gtfo:
                                    triggered = True
                                    findings.append(
                                        f"⚠️ [DANGEROUS GTFOBin] {flag_type} File: {entry.path} "
                                        f"(Known privilege escalation risk)"
                                    )
                                else:
                                    findings.append(f"Standard/Other {flag_type} File: {entry.path}")
                                    
                        except (PermissionError, FileNotFoundError):
                            continue
            except Exception as e:
                findings.append(f"Error scanning directory {search_dir}: {str(e)}")

        return CheckResult(
            check_name=self.name,
            category=self.category,
            severity=self.severity if triggered else "Low" if findings else "Info",
            triggered=triggered,
            details=findings if findings else ["No SUID/SGID files found in standard system directories."],
            recommendation=recommendation if triggered else ""
        )
