
from executor.policy import Decision, Policy

policy = Policy("192.0.2.10")

checks = [
    ("Authorized target",
     policy.check_target("192.0.2.10"),
     Decision.ALLOW),

    ("Other target",
     policy.check_target("192.0.2.11"),
     Decision.DENY),

    ("Workspace file",
     policy.check_path("artifacts/result.txt"),
     Decision.ALLOW),

    ("Outside workspace",
     policy.check_path("/etc/shadow"),
     Decision.DENY),

    ("Path traversal",
     policy.check_path("../../etc/passwd"),
     Decision.DENY),

    ("Save finding",
     policy.check_operation("save_finding"),
     Decision.ALLOW),

    ("Privilege escalation",
     policy.check_operation("privilege_escalation"),
     Decision.APPROVAL),

    ("Host package install",
     policy.check_operation("host_package_install"),
     Decision.APPROVAL),

    ("Unknown operation",
     policy.check_operation("arbitrary_shell"),
     Decision.DENY),
]

for label, actual, expected in checks:
    assert actual == expected, (
        f"{label}: expected {expected}, got {actual}"
    )
    print(f"[PASS] {label}: {actual.value}")

print("\n[SUCCESS] All policy tests passed")
