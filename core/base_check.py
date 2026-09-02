import abc

class CheckResult:
    """Represents the outcome of an auditing check."""
    def __init__(self, check_name, category, severity, triggered=False, details=None, recommendation="", description=""):
        self.check_name = check_name
        self.category = category
        self.severity = severity  # 'Critical', 'High', 'Medium', 'Low', 'Info'
        self.triggered = triggered  # True if vulnerability/misconfiguration found
        self.details = details or []  # List of findings (strings, dicts, etc.)
        self.recommendation = recommendation
        self.description = description

    def to_dict(self):
        return {
            "check_name": self.check_name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "triggered": self.triggered,
            "details": self.details,
            "recommendation": self.recommendation
        }



class BaseCheck(abc.ABC):
    """Abstract Base Class for all audit checks."""
    
    def __init__(self):
        pass

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the check."""
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Short description of what the check looks for."""
        pass

    @property
    @abc.abstractmethod
    def category(self) -> str:
        """Category of the check (e.g., Services, Registry, Filesystem)."""
        pass

    @property
    @abc.abstractmethod
    def severity(self) -> str:
        """Default severity level ('Critical', 'High', 'Medium', 'Low', 'Info')."""
        pass

    @abc.abstractmethod
    def run(self) -> CheckResult:
        """Executes the check and returns a CheckResult."""
        pass
