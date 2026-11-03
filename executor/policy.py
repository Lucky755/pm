
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from pathlib import Path


WORKSPACE = Path("/home/lucky/pentest-master").resolve()


class Decision(str, Enum):
    ALLOW = "allow"
    APPROVAL = "approval_required"
    DENY = "deny"


@dataclass(frozen=True)
class Policy:
    authorized_target: str

    def __post_init__(self):
        # This first version supports one exact IP address.
        ip_address(self.authorized_target)

    def check_target(self, target: str) -> Decision:
        try:
            candidate = ip_address(target)
            authorized = ip_address(self.authorized_target)
        except ValueError:
            return Decision.DENY

        return (
            Decision.ALLOW
            if candidate == authorized
            else Decision.DENY
        )

    def check_path(self, path: str) -> Decision:
        candidate = Path(path)

        if not candidate.is_absolute():
            candidate = WORKSPACE / candidate

        try:
            resolved = candidate.resolve()
            resolved.relative_to(WORKSPACE)
        except (ValueError, OSError, RuntimeError):
            return Decision.DENY

        return Decision.ALLOW

    def check_operation(self, operation: str) -> Decision:
        approvals = {
            "privilege_escalation",
            "host_package_install",
            "host_system_change",
            "destructive_operation",
        }

        permitted = {
            "read_findings",
            "save_finding",
            "notify",
            "workspace_write",
            "workspace_tool_install",
            "authorized_target_scan",
        }

        if operation in approvals:
            return Decision.APPROVAL

        if operation in permitted:
            return Decision.ALLOW

        return Decision.DENY
