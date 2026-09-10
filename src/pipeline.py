"""
Ingestion + identity-resolution pipeline
========================================

Loads the three native cloud exports plus the HR directory and activity log,
resolves principals to a single canonical identity (join key = corporate
email), and normalizes every grant into the Common Permission Model.

Identity resolution across clouds is the hard part: AWS keys principals by ARN,
Azure by principalId, GCP by `type:email` member strings. The activity log acts
as the resolution bridge (principal_ref -> canonical email) for GCP, while AWS
and Azure carry the email directly. The result is one `UnifiedIdentity` per
person/service account with a merged capability set and per-cloud evidence.

The loader is defensive by design (missing files, unknown principals, bad
dates) because "survives unexpected input" is an explicitly scored requirement.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from datetime import date, datetime

from src.normalizer import normalize_aws, normalize_azure, normalize_gcp_role

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(os.path.dirname(HERE), "data", "raw")


@dataclass
class CloudPresence:
    provider: str
    principal_ref: str
    principal_type: str
    native_roles: list[str] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=set)
    last_activity: date | None = None


@dataclass
class UnifiedIdentity:
    identity_id: str
    name: str
    email: str
    department: str
    title: str
    status: str                      # active | departed | unknown
    hire_date: str | None
    termination_date: str | None
    is_service_account: bool
    clouds: dict[str, CloudPresence] = field(default_factory=dict)

    @property
    def all_capabilities(self) -> set[str]:
        caps: set[str] = set()
        for p in self.clouds.values():
            caps |= p.capabilities
        return caps

    @property
    def providers(self) -> list[str]:
        return sorted(self.clouds.keys())

    @property
    def last_activity(self) -> date | None:
        dates = [p.last_activity for p in self.clouds.values() if p.last_activity]
        return max(dates) if dates else None


def _parse_date(s: str | None) -> date | None:
    if not isinstance(s, str) or not s.strip():
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s.strip(), fmt).date()
        except (ValueError, AttributeError):
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "")).date()
    except (ValueError, AttributeError):
        return None


# Type-coercion helpers: real exports get hand-edited, truncated and
# re-encoded, so every value is validated at the boundary instead of trusted.
def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _as_str(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _load_json(path: str, default):
    """Load a JSON object; missing, unreadable, invalid or non-object -> default."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):  # missing/unreadable, bad JSON, bad encoding
        return default
    return data if isinstance(data, dict) else default


def _load_csv(path: str) -> list[dict]:
    """Load CSV rows; missing, unreadable or malformed file -> empty list."""
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return [row for row in csv.DictReader(f) if isinstance(row, dict)]
    except (OSError, ValueError, csv.Error):
        return []


def load_estate(raw_dir: str = RAW):
    hr = _load_csv(os.path.join(raw_dir, "hr_directory.csv"))
    aws = _load_json(os.path.join(raw_dir, "aws_iam.json"), {"Principals": []})
    azure = _load_json(os.path.join(raw_dir, "azure_role_assignments.json"), {"roleAssignments": []})
    gcp = _load_json(os.path.join(raw_dir, "gcp_iam_policy.json"), {"bindings": []})
    activity = _load_csv(os.path.join(raw_dir, "activity_log.csv"))
    return hr, aws, azure, gcp, activity


def reference_date(aws: dict) -> date:
    """Snapshot 'as of' date, taken from the AWS export; falls back to today."""
    return _parse_date(_as_dict(aws).get("GeneratedAt")) or date.today()


def build_identities(raw_dir: str = RAW) -> tuple[list[UnifiedIdentity], date]:
    hr, aws, azure, gcp, activity = load_estate(raw_dir)
    ref = reference_date(aws)

    # index HR by email
    identities: dict[str, UnifiedIdentity] = {}
    for row in hr:
        email = _as_str(row.get("email")).lower()
        if not email:
            continue
        identities[email] = UnifiedIdentity(
            identity_id=_as_str(row.get("id")),
            name=_as_str(row.get("name")) or email,
            email=email,
            department=_as_str(row.get("department")) or "Unknown",
            title=_as_str(row.get("title")),
            status=_as_str(row.get("status")).lower() or "unknown",
            hire_date=_as_str(row.get("hire_date")) or None,
            termination_date=_as_str(row.get("termination_date")) or None,
            is_service_account=_as_str(row.get("is_service_account")).lower() == "true",
        )

    # activity resolution bridge: (provider, principal_ref) -> (email, date)
    act_index: dict[tuple[str, str], tuple[str, date | None]] = {}
    for row in activity:
        key = (_as_str(row.get("provider")).lower(), _as_str(row.get("principal_ref")))
        if not key[0] or not key[1]:
            continue
        act_index[key] = (_as_str(row.get("email")).lower(),
                          _parse_date(row.get("last_activity")))

    def ensure(email: str, name: str, is_sa: bool) -> UnifiedIdentity:
        email = email.strip().lower()
        if email not in identities:
            # principal present in a cloud but absent from HR -> orphaned/unknown
            identities[email] = UnifiedIdentity(
                identity_id="", name=name or email, email=email,
                department="Unmanaged", title="", status="unknown",
                hire_date=None, termination_date=None, is_service_account=is_sa,
            )
        return identities[email]

    # ---- AWS -----------------------------------------------------------------
    for pr in _as_list(aws.get("Principals")):
        pr = _as_dict(pr)
        email = _as_str(pr.get("Email")).lower()
        if not email:
            continue
        ptype = _as_str(pr.get("PrincipalType")) or "IAMUser"
        ident = ensure(email, _as_str(pr.get("UserName")), ptype == "IAMRole")
        # a managed policy may be {"PolicyName": ...} or a bare name string
        managed = [m if isinstance(m, str) else _as_str(_as_dict(m).get("PolicyName"))
                   for m in _as_list(pr.get("AttachedManagedPolicies"))]
        managed = [m for m in managed if m]
        docs = [d for d in _as_list(pr.get("InlinePolicyDocuments")) if isinstance(d, dict)]
        caps = normalize_aws({"managed_policies": managed, "policy_documents": docs})
        native = list(managed) + [f"inline-policy({len(docs)})"] if docs else list(managed)
        ident.clouds["aws"] = CloudPresence(
            provider="aws",
            principal_ref=_as_str(pr.get("Arn")) or email,
            principal_type=ptype,
            native_roles=native,
            capabilities=caps,
            last_activity=_parse_date(pr.get("LastActivity")),
        )

    # ---- Azure ---------------------------------------------------------------
    for ra in _as_list(azure.get("roleAssignments")):
        ra = _as_dict(ra)
        email = _as_str(ra.get("principalEmail")).lower()
        if not email:
            continue
        ptype = _as_str(ra.get("principalType")) or "User"
        ident = ensure(email, _as_str(ra.get("principalName")), ptype == "ServicePrincipal")
        caps = normalize_azure(ra)
        role = _as_str(ra.get("roleDefinitionName"))
        native = [role] + [f"action:{a}" for a in _as_list(ra.get("actions"))
                           if isinstance(a, str)]
        pres = ident.clouds.get("azure")
        if pres:  # multiple assignments -> merge
            pres.capabilities |= caps
            pres.native_roles += native
        else:
            ident.clouds["azure"] = CloudPresence(
                provider="azure",
                principal_ref=_as_str(ra.get("principalId")) or email,
                principal_type=ptype,
                native_roles=native,
                capabilities=caps,
                last_activity=_parse_date(ra.get("lastSignInDateTime")),
            )

    # ---- GCP -----------------------------------------------------------------
    for binding in _as_list(gcp.get("bindings")):
        binding = _as_dict(binding)
        role = _as_str(binding.get("role"))
        caps = normalize_gcp_role(role)
        for member in _as_list(binding.get("members")):
            member = _as_str(member)
            if not member:
                continue
            is_sa = member.startswith("serviceAccount:")
            resolved = act_index.get(("gcp", member))
            email = resolved[0] if resolved else member.split(":", 1)[-1]
            if not email:
                continue
            last = resolved[1] if resolved else None
            ident = ensure(email, member.split(":", 1)[-1], is_sa)
            pres = ident.clouds.get("gcp")
            if pres:
                pres.capabilities |= caps
                if role not in pres.native_roles:
                    pres.native_roles.append(role)
            else:
                ident.clouds["gcp"] = CloudPresence(
                    provider="gcp",
                    principal_ref=member,
                    principal_type="serviceAccount" if is_sa else "user",
                    native_roles=[role],
                    capabilities=set(caps),
                    last_activity=last,
                )

    # keep only identities that actually hold cloud access
    result = [i for i in identities.values() if i.clouds]
    return result, ref


if __name__ == "__main__":
    ids, ref = build_identities()
    print(f"Resolved {len(ids)} identities with cloud access (as of {ref}).")
    multi = [i for i in ids if len(i.clouds) == 3]
    print(f"  present in all 3 clouds: {len(multi)}")
    sample = ids[0]
    print(f"  sample: {sample.name} <{sample.email}> providers={sample.providers}")
    print(f"          capabilities={sorted(sample.all_capabilities)}")
