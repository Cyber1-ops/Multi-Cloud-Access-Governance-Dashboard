"""
Synthetic multi-cloud estate generator
=======================================

Produces a realistic 500-identity government hybrid estate across three clouds,
each written in its own *native* export format so the normalizer has real work
to do:

    data/raw/hr_directory.csv            HR system of record (departments, leavers)
    data/raw/aws_iam.json                AWS IAM (per-principal managed + inline policies)
    data/raw/azure_role_assignments.json Azure RBAC (flat role-assignment list)
    data/raw/gcp_iam_policy.json         GCP IAM (role -> members bindings)
    data/raw/activity_log.csv            unified last-activity signal per principal

The generator is fully deterministic (fixed seed) so the demo is reproducible
and the prototype "survives a second run" (a scored requirement). It also
*scripts in* a handful of known-bad identities so the demo's top findings are
guaranteed and explainable, on top of a randomly generated background estate.
"""

from __future__ import annotations

import csv
import json
import os
import random
from datetime import date, timedelta

SEED = 42
AS_OF = date(2026, 9, 8)          # "today" for activity calculations
TOTAL_IDENTITIES = 500
HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")

AWS_ACCOUNT = "gov-aws-prod-001"
AZURE_SUB = "gov-azure-sub-9f2a"
GCP_PROJECT = "gov-gcp-prod"

DEPARTMENTS = [
    "Executive", "IT", "Security", "Finance", "HR",
    "Legal", "Operations", "Procurement", "Engineering", "Health Services",
]

FIRST_NAMES = [
    "Ahmad", "Fatima", "Omar", "Aisha", "Yousef", "Mariam", "Khalid", "Noura",
    "Saeed", "Hana", "Rashid", "Layla", "Hamdan", "Salma", "Tariq", "Reem",
    "Majid", "Amal", "Faisal", "Huda", "Nasser", "Dana", "Sultan", "Maha",
    "Zayed", "Latifa", "Bilal", "Shaikha", "Adel", "Wafa", "James", "Sofia",
    "Liam", "Emma", "Noah", "Olivia", "Arun", "Priya", "Wei", "Mei",
]
LAST_NAMES = [
    "Al Marri", "Al Nuaimi", "Al Suwaidi", "Al Hashimi", "Al Mansoori",
    "Al Balushi", "Khan", "Sharma", "Haddad", "Nassar", "Rahman", "Farah",
    "Ibrahim", "Saleh", "Osman", "Kamal", "Aziz", "Habib", "Zaman", "Qureshi",
    "Smith", "Johnson", "Chen", "Wang", "Patel", "Kumar", "Costa", "Silva",
]


def daysago(n: int) -> str:
    return (AS_OF - timedelta(days=n)).isoformat()


# ---------------------------------------------------------------------------
# Identity population
# ---------------------------------------------------------------------------

def build_population(rng: random.Random) -> list[dict]:
    """Create the canonical list of identities (before cloud placement)."""
    used_emails: set[str] = set()
    people: list[dict] = []

    n_service = 70
    n_human = TOTAL_IDENTITIES - n_service

    for i in range(n_human):
        first = rng.choice(FIRST_NAMES)
        last = rng.choice(LAST_NAMES)
        base = f"{first}.{last}".lower().replace(" ", "")
        email = f"{base}@gov.ae"
        n = 2
        while email in used_emails:
            email = f"{base}{n}@gov.ae"
            n += 1
        used_emails.add(email)

        dept = rng.choice(DEPARTMENTS)
        # ~9% of staff have left the organisation.
        departed = rng.random() < 0.09
        hire = AS_OF - timedelta(days=rng.randint(200, 3000))
        term = None
        if departed:
            term = (AS_OF - timedelta(days=rng.randint(5, 400))).isoformat()

        people.append({
            "id": f"U{i:04d}",
            "first": first, "last": last,
            "name": f"{first} {last}",
            "email": email,
            "department": dept,
            "title": rng.choice(["Analyst", "Engineer", "Manager", "Specialist",
                                  "Director", "Administrator", "Officer"]),
            "is_service_account": False,
            "status": "departed" if departed else "active",
            "hire_date": hire.isoformat(),
            "termination_date": term,
        })

    for i in range(n_service):
        purpose = rng.choice(["backup", "etl", "ci", "monitoring", "billing-sync",
                              "data-pipeline", "vm-agent", "scanner", "reporting"])
        name = f"svc-{purpose}-{i:03d}"
        people.append({
            "id": f"S{i:04d}",
            "first": name, "last": "",
            "name": name,
            "email": f"{name}@service.gov.ae",
            "department": "Service Accounts",
            "title": "Service Account",
            "is_service_account": True,
            "status": "active",
            "hire_date": (AS_OF - timedelta(days=rng.randint(100, 2000))).isoformat(),
            "termination_date": None,
        })

    return people


# ---------------------------------------------------------------------------
# Cloud grant catalogues (native role/policy pools)
# ---------------------------------------------------------------------------

AWS_MANAGED_POOL = [
    "ReadOnlyAccess", "AmazonS3ReadOnlyAccess", "AmazonS3FullAccess",
    "AmazonEC2FullAccess", "AmazonRDSFullAccess", "PowerUserAccess", "Billing",
]
AZURE_ROLE_POOL = [
    "Reader", "Storage Blob Data Reader", "Storage Blob Data Contributor",
    "Virtual Machine Contributor", "Network Contributor", "SQL DB Contributor",
    "Contributor", "Monitoring Reader", "Billing Reader",
]
GCP_ROLE_POOL = [
    "roles/viewer", "roles/storage.objectViewer", "roles/storage.objectAdmin",
    "roles/compute.viewer", "roles/compute.admin", "roles/cloudsql.admin",
    "roles/editor", "roles/logging.viewer", "roles/billing.viewer",
]


def aws_inline_read_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket", "logs:GetLogEvents"],
            "Resource": "*",
        }],
    }


def aws_toxic_policy() -> dict:
    """Inline policy granting a create-role + assign-role escalation path."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PassRole"],
            "Resource": "*",
        }],
    }


# ---------------------------------------------------------------------------
# Estate assembly
# ---------------------------------------------------------------------------

def generate(rng: random.Random):
    people = build_population(rng)

    aws_principals: list[dict] = []
    azure_assignments: list[dict] = []
    gcp_bindings: dict[str, list[str]] = {}
    gcp_service_accounts: list[dict] = []
    activity_rows: list[dict] = []

    def add_gcp_member(role: str, member: str):
        gcp_bindings.setdefault(role, [])
        if member not in gcp_bindings[role]:
            gcp_bindings[role].append(member)

    def record_activity(provider, principal_ref, email, last_active_days):
        activity_rows.append({
            "provider": provider,
            "principal_ref": principal_ref,
            "email": email,
            "last_activity": daysago(last_active_days),
        })

    # ---- scripted high-risk identities (guaranteed demo findings) ----------
    scripted_ids = set()

    def pick(pred, k):
        cands = [p for p in people if pred(p) and p["id"] not in scripted_ids]
        chosen = rng.sample(cands, min(k, len(cands)))
        for c in chosen:
            scripted_ids.add(c["id"])
        return chosen

    # 3 cross-cloud superusers (admin in all three clouds) - top demo finding.
    for p in pick(lambda p: not p["is_service_account"] and p["status"] == "active", 3):
        p["_scenario"] = "cross_cloud_superuser"
    # 4 departed staff who still hold admin access.
    for p in pick(lambda p: p["status"] == "departed", 4):
        p["_scenario"] = "departed_admin"
    # 5 toxic-combo escalation identities.
    for p in pick(lambda p: not p["is_service_account"] and p["status"] == "active", 5):
        p["_scenario"] = "toxic_combo"
    # 6 orphaned, stale service accounts with broad rights.
    for p in pick(lambda p: p["is_service_account"], 6):
        p["_scenario"] = "orphaned_sa"

    # ---- place every identity into 1..3 clouds -----------------------------
    for p in people:
        scenario = p.get("_scenario")
        email = p["email"]

        # Decide cloud presence.
        if scenario in ("cross_cloud_superuser",):
            clouds = {"aws", "azure", "gcp"}
        else:
            k = rng.choices([1, 2, 3], weights=[45, 35, 20])[0]
            clouds = set(rng.sample(["aws", "azure", "gcp"], k))
            clouds.add(rng.choice(["aws", "azure", "gcp"]))

        # Activity age: orphaned/departed skew very stale.
        if scenario in ("orphaned_sa", "departed_admin"):
            act_days = rng.randint(120, 500)
        elif rng.random() < 0.18:
            act_days = rng.randint(95, 300)      # background stale population
        else:
            act_days = rng.randint(0, 80)

        # ---- AWS ----------------------------------------------------------
        if "aws" in clouds:
            managed, docs = [], []
            if scenario == "cross_cloud_superuser" or scenario == "departed_admin":
                managed = ["AdministratorAccess"]
            elif scenario == "toxic_combo":
                docs = [aws_toxic_policy()]
                managed = ["AmazonS3ReadOnlyAccess"]
            elif scenario == "orphaned_sa":
                managed = ["PowerUserAccess"]
            else:
                managed = rng.sample(AWS_MANAGED_POOL, rng.randint(1, 2))
                if rng.random() < 0.5:
                    docs = [aws_inline_read_policy()]
            arn_kind = "role" if p["is_service_account"] else "user"
            name = p["name"].replace(" ", ".").lower() if not p["is_service_account"] else p["first"]
            ref = f"arn:aws:iam::111122223333:{arn_kind}/{name}"
            aws_principals.append({
                "PrincipalType": "IAMRole" if p["is_service_account"] else "IAMUser",
                "UserName": name,
                "Arn": ref,
                "Email": email,
                "AttachedManagedPolicies": [
                    {"PolicyName": m, "PolicyArn": f"arn:aws:iam::aws:policy/{m}"} for m in managed
                ],
                "InlinePolicyDocuments": docs,
                "LastActivity": daysago(act_days),
            })
            record_activity("aws", ref, email, act_days)

        # ---- Azure --------------------------------------------------------
        if "azure" in clouds:
            if scenario in ("cross_cloud_superuser", "departed_admin"):
                role, actions = "Owner", []
            elif scenario == "toxic_combo":
                role = "Custom - Access Deployer"
                actions = ["Microsoft.Authorization/roleAssignments/write",
                           "Microsoft.Authorization/roleDefinitions/write"]
            elif scenario == "orphaned_sa":
                role, actions = "Contributor", []
            else:
                role, actions = rng.choice(AZURE_ROLE_POOL), []
            azure_assignments.append({
                "principalId": f"{rng.randrange(16**8):08x}-0000-4000-8000-{rng.randrange(16**12):012x}",
                "principalType": "ServicePrincipal" if p["is_service_account"] else "User",
                "principalName": p["name"],
                "principalEmail": email,
                "roleDefinitionName": role,
                "actions": actions,
                "scope": f"/subscriptions/{AZURE_SUB}/resourceGroups/rg-prod",
                "lastSignInDateTime": daysago(act_days),
            })
            record_activity("azure", email, email, act_days)

        # ---- GCP ----------------------------------------------------------
        if "gcp" in clouds:
            prefix = "serviceAccount" if p["is_service_account"] else "user"
            if p["is_service_account"]:
                member_email = f"{p['first']}@{GCP_PROJECT}.iam.gserviceaccount.com"
            else:
                member_email = email
            member = f"{prefix}:{member_email}"

            if scenario in ("cross_cloud_superuser", "departed_admin"):
                roles = ["roles/owner"]
            elif scenario == "toxic_combo":
                roles = ["roles/iam.roleAdmin", "roles/iam.serviceAccountTokenCreator",
                         "roles/storage.objectViewer"]
            elif scenario == "orphaned_sa":
                roles = ["roles/editor"]
            else:
                roles = rng.sample(GCP_ROLE_POOL, rng.randint(1, 2))
            for r in roles:
                add_gcp_member(r, member)
            if p["is_service_account"]:
                gcp_service_accounts.append({
                    "email": member_email,
                    "displayName": p["name"],
                    "disabled": False,
                })
            record_activity("gcp", member, email, act_days)

    # strip internal scenario markers from HR output
    for p in people:
        p.pop("_scenario", None)

    return {
        "people": people,
        "aws": {"Account": AWS_ACCOUNT, "GeneratedAt": AS_OF.isoformat(),
                "Principals": aws_principals},
        "azure": {"subscriptionId": AZURE_SUB, "generatedAt": AS_OF.isoformat(),
                  "roleAssignments": azure_assignments},
        "gcp": {"project": GCP_PROJECT, "generatedAt": AS_OF.isoformat(),
                "bindings": [{"role": r, "members": m} for r, m in sorted(gcp_bindings.items())],
                "serviceAccounts": gcp_service_accounts},
        "activity": activity_rows,
    }


def write_all(estate: dict):
    os.makedirs(RAW, exist_ok=True)

    with open(os.path.join(RAW, "hr_directory.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "id", "name", "email", "department", "title", "status",
            "hire_date", "termination_date", "is_service_account",
        ])
        w.writeheader()
        for p in estate["people"]:
            w.writerow({k: p.get(k, "") for k in w.fieldnames})

    with open(os.path.join(RAW, "aws_iam.json"), "w", encoding="utf-8") as f:
        json.dump(estate["aws"], f, indent=2)
    with open(os.path.join(RAW, "azure_role_assignments.json"), "w", encoding="utf-8") as f:
        json.dump(estate["azure"], f, indent=2)
    with open(os.path.join(RAW, "gcp_iam_policy.json"), "w", encoding="utf-8") as f:
        json.dump(estate["gcp"], f, indent=2)

    with open(os.path.join(RAW, "activity_log.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["provider", "principal_ref", "email", "last_activity"])
        w.writeheader()
        w.writerows(estate["activity"])


def main():
    rng = random.Random(SEED)
    estate = generate(rng)
    write_all(estate)
    n_people = len(estate["people"])
    n_aws = len(estate["aws"]["Principals"])
    n_azure = len(estate["azure"]["roleAssignments"])
    n_gcp = sum(len(b["members"]) for b in estate["gcp"]["bindings"])
    print(f"Generated estate as of {AS_OF.isoformat()}")
    print(f"  identities        : {n_people}")
    print(f"  AWS principals    : {n_aws}")
    print(f"  Azure assignments : {n_azure}")
    print(f"  GCP bindings mbrs : {n_gcp}")
    print(f"  files written to  : {RAW}")


if __name__ == "__main__":
    main()
