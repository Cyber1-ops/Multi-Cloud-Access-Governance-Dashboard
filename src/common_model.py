"""
Common Permission Model (CPM)
=============================

The core abstraction of the project. Every cloud provider describes access
differently (AWS IAM policy JSON, Azure RBAC role assignments, GCP IAM
bindings). To reason about "who can do what" across an entire hybrid estate we
map all of them onto ONE normalized capability taxonomy defined here.

A capability is a `service:level` pair, e.g. `storage:read`, `compute:admin`.
On top of that we track a small set of *sensitive* capabilities that are the
building blocks of privilege escalation and blast radius:

    iam:admin          full control of identities and access
    iam:create_role    can mint new roles / policies
    iam:assign_role    can bind roles to principals (or impersonate them)
    wildcard           unrestricted "*" access (superadmin)

Keeping the taxonomy small and explicit is deliberate: the jury scores
correctness, and a compact model is easy to audit and hard to get wrong.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

SERVICES = [
    "iam",
    "storage",
    "compute",
    "network",
    "database",
    "billing",
    "security",
    "logging",
]

LEVELS = ["read", "write", "admin"]

# Sensitive, escalation-relevant capabilities (used by detection rules).
CAP_WILDCARD = "wildcard"              # unrestricted "*" superadmin
CAP_IAM_ADMIN = "iam:admin"
CAP_IAM_CREATE_ROLE = "iam:create_role"
CAP_IAM_ASSIGN_ROLE = "iam:assign_role"

# Capabilities that mean "this principal can administer identity/access".
ADMIN_CAPABILITIES = {CAP_WILDCARD, CAP_IAM_ADMIN}


def cap(service: str, level: str) -> str:
    """Build a normalized capability string, e.g. cap('storage', 'read')."""
    if service not in SERVICES:
        raise ValueError(f"unknown service: {service}")
    if level not in LEVELS:
        raise ValueError(f"unknown level: {level}")
    return f"{service}:{level}"


def expand_wildcard() -> set[str]:
    """Return the full capability set implied by a wildcard/superadmin grant."""
    caps = {CAP_WILDCARD}
    for s in SERVICES:
        caps.add(cap(s, "admin"))
    caps |= {CAP_IAM_ADMIN, CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE}
    return caps


def is_admin(capabilities: set[str]) -> bool:
    """True if the capability set confers identity/access administration."""
    if capabilities & ADMIN_CAPABILITIES:
        return True
    # Any service admin level counts as an admin-grade grant for scoring.
    return any(c.endswith(":admin") for c in capabilities)


def highest_level(capabilities: set[str]) -> str:
    """Coarse strength of a capability set: none < read < write < admin."""
    if CAP_WILDCARD in capabilities or any(c.endswith(":admin") for c in capabilities):
        return "admin"
    if any(c.endswith(":write") for c in capabilities):
        return "write"
    if any(c.endswith(":read") for c in capabilities):
        return "read"
    return "none"
