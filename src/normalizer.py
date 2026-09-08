"""
Normalizer
==========

Translates provider-specific access grants into the Common Permission Model
(see common_model.py). Each provider speaks a different dialect:

    AWS   -> IAM policy documents (Statement / Action / Resource)
    Azure -> RBAC role assignments (roleDefinitionName + optional actions[])
    GCP   -> IAM policy bindings (role -> members)

Every mapper returns a `set[str]` of normalized capabilities. This is where
most of the "technical depth" lives, so the mappings are explicit and
conservative: when in doubt we *raise* the modelled privilege rather than hide
it, because an access-governance tool must not under-report risk.
"""

from __future__ import annotations

from src.common_model import (
    CAP_IAM_ADMIN,
    CAP_IAM_ASSIGN_ROLE,
    CAP_IAM_CREATE_ROLE,
    CAP_WILDCARD,
    cap,
    expand_wildcard,
)

# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

# AWS service-prefix -> our service taxonomy.
_AWS_PREFIX_TO_SERVICE = {
    "iam": "iam",
    "sts": "iam",
    "organizations": "iam",
    "s3": "storage",
    "ec2": "compute",
    "lambda": "compute",
    "rds": "database",
    "dynamodb": "database",
    "vpc": "network",
    "elasticloadbalancing": "network",
    "kms": "security",
    "secretsmanager": "security",
    "cloudtrail": "logging",
    "logs": "logging",
    "ce": "billing",
    "budgets": "billing",
    "aws-portal": "billing",
}

# AWS managed policies with well-known blast radius.
_AWS_MANAGED = {
    "AdministratorAccess": "wildcard",
    "IAMFullAccess": "iam_admin",
    "PowerUserAccess": "poweruser",  # everything except IAM admin
    "ReadOnlyAccess": "readonly",
    "AmazonS3FullAccess": ("storage", "admin"),
    "AmazonS3ReadOnlyAccess": ("storage", "read"),
    "AmazonEC2FullAccess": ("compute", "admin"),
    "AmazonRDSFullAccess": ("database", "admin"),
    "Billing": ("billing", "admin"),
}

# Specific IAM actions that are escalation primitives.
_AWS_ESCALATION = {
    "iam:createrole": CAP_IAM_CREATE_ROLE,
    "iam:createpolicy": CAP_IAM_CREATE_ROLE,
    "iam:createpolicyversion": CAP_IAM_CREATE_ROLE,
    "iam:attachrolepolicy": CAP_IAM_ASSIGN_ROLE,
    "iam:attachuserpolicy": CAP_IAM_ASSIGN_ROLE,
    "iam:putrolepolicy": CAP_IAM_ASSIGN_ROLE,
    "iam:putuserpolicy": CAP_IAM_ASSIGN_ROLE,
    "iam:passrole": CAP_IAM_ASSIGN_ROLE,
    "sts:assumerole": CAP_IAM_ASSIGN_ROLE,
}

_READ_VERBS = ("get", "list", "describe", "read", "view", "head")
_WRITE_VERBS = ("create", "put", "update", "delete", "modify", "write", "attach", "detach", "run")


def _aws_level_from_action(action_suffix: str) -> str:
    a = action_suffix.lower()
    if a == "*":
        return "admin"
    if a.startswith(_READ_VERBS):
        return "read"
    if a.startswith(_WRITE_VERBS):
        return "write"
    return "write"  # unknown mutating-looking action -> conservative


def normalize_aws(aws_principal: dict) -> set[str]:
    """Normalize one AWS principal record into common capabilities."""
    caps: set[str] = set()

    for policy_name in aws_principal.get("managed_policies", []):
        rule = _AWS_MANAGED.get(policy_name)
        if rule == "wildcard":
            return expand_wildcard()
        if rule == "iam_admin":
            caps |= {CAP_IAM_ADMIN, CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE, cap("iam", "admin")}
        elif rule == "poweruser":
            for s in ("storage", "compute", "network", "database", "security", "logging"):
                caps.add(cap(s, "admin"))
        elif rule == "readonly":
            from src.common_model import SERVICES
            for s in SERVICES:
                caps.add(cap(s, "read"))
        elif isinstance(rule, tuple):
            caps.add(cap(rule[0], rule[1]))

    # Inline / attached policy documents.
    for doc in aws_principal.get("policy_documents", []):
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*":
                    return expand_wildcard()
                if ":" not in action:
                    continue
                prefix, suffix = action.split(":", 1)
                full = action.lower()
                if full in _AWS_ESCALATION:
                    caps.add(_AWS_ESCALATION[full])
                service = _AWS_PREFIX_TO_SERVICE.get(prefix.lower())
                if not service:
                    continue
                if suffix == "*":
                    caps.add(cap(service, "admin"))
                    if service == "iam":
                        caps |= {CAP_IAM_ADMIN, CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE}
                else:
                    caps.add(cap(service, _aws_level_from_action(suffix)))
    return caps


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

_AZURE_BUILTIN = {
    "Owner": "wildcard",
    "Contributor": "contributor",  # write on everything, no access mgmt
    "Reader": "reader",
    "User Access Administrator": "uaa",  # manage access only
    "Storage Blob Data Owner": ("storage", "admin"),
    "Storage Blob Data Contributor": ("storage", "write"),
    "Storage Blob Data Reader": ("storage", "read"),
    "Virtual Machine Contributor": ("compute", "write"),
    "Network Contributor": ("network", "write"),
    "SQL DB Contributor": ("database", "write"),
    "Security Admin": ("security", "admin"),
    "Key Vault Administrator": ("security", "admin"),
    "Monitoring Reader": ("logging", "read"),
    "Billing Reader": ("billing", "read"),
    "Cost Management Contributor": ("billing", "write"),
}

_AZURE_ACTION_MAP = {
    "microsoft.authorization/roleassignments/write": CAP_IAM_ASSIGN_ROLE,
    "microsoft.authorization/roledefinitions/write": CAP_IAM_CREATE_ROLE,
    "microsoft.authorization/*": CAP_IAM_ADMIN,
    "*": None,  # handled as wildcard
}


def normalize_azure(azure_assignment: dict) -> set[str]:
    """Normalize one Azure role assignment into common capabilities."""
    from src.common_model import SERVICES

    caps: set[str] = set()
    role = azure_assignment.get("roleDefinitionName", "")
    rule = _AZURE_BUILTIN.get(role)

    if rule == "wildcard":
        return expand_wildcard()
    if rule == "contributor":
        for s in ("storage", "compute", "network", "database", "security", "logging"):
            caps.add(cap(s, "write"))
    elif rule == "reader":
        for s in SERVICES:
            caps.add(cap(s, "read"))
    elif rule == "uaa":
        caps |= {CAP_IAM_ADMIN, CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE, cap("iam", "admin")}
    elif isinstance(rule, tuple):
        caps.add(cap(rule[0], rule[1]))

    # Custom roles carry an explicit actions[] list.
    for action in azure_assignment.get("actions", []):
        a = action.lower()
        if a == "*":
            return expand_wildcard()
        mapped = _AZURE_ACTION_MAP.get(a)
        if mapped:
            caps.add(mapped)
            if mapped == CAP_IAM_ADMIN:
                caps |= {CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE, cap("iam", "admin")}
    return caps


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------

_GCP_ROLE_MAP = {
    "roles/owner": "wildcard",
    "roles/editor": "editor",
    "roles/viewer": "viewer",
    "roles/iam.securityAdmin": "iam_full",
    "roles/iam.admin": "iam_full",
    "roles/resourcemanager.projectIamAdmin": "iam_full",
    "roles/iam.serviceAccountAdmin": ("iam", "admin"),
    "roles/iam.roleAdmin": CAP_IAM_CREATE_ROLE,
    "roles/iam.serviceAccountTokenCreator": CAP_IAM_ASSIGN_ROLE,
    "roles/iam.serviceAccountUser": CAP_IAM_ASSIGN_ROLE,
    "roles/storage.admin": ("storage", "admin"),
    "roles/storage.objectAdmin": ("storage", "write"),
    "roles/storage.objectViewer": ("storage", "read"),
    "roles/compute.admin": ("compute", "admin"),
    "roles/compute.viewer": ("compute", "read"),
    "roles/cloudsql.admin": ("database", "admin"),
    "roles/compute.networkAdmin": ("network", "admin"),
    "roles/cloudkms.admin": ("security", "admin"),
    "roles/logging.viewer": ("logging", "read"),
    "roles/billing.admin": ("billing", "admin"),
    "roles/billing.viewer": ("billing", "read"),
}


def normalize_gcp_role(role: str) -> set[str]:
    """Normalize a single GCP role string into common capabilities."""
    from src.common_model import SERVICES

    caps: set[str] = set()
    rule = _GCP_ROLE_MAP.get(role)
    if rule == "wildcard":
        return expand_wildcard()
    if rule == "editor":
        for s in ("storage", "compute", "network", "database", "security", "logging"):
            caps.add(cap(s, "write"))
    elif rule == "viewer":
        for s in SERVICES:
            caps.add(cap(s, "read"))
    elif rule == "iam_full":
        caps |= {CAP_IAM_ADMIN, CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE, cap("iam", "admin")}
    elif isinstance(rule, tuple):
        caps.add(cap(rule[0], rule[1]))
    elif isinstance(rule, str):  # a bare escalation capability constant
        caps.add(rule)
    return caps
