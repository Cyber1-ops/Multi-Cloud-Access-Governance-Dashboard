"""
Normalizer correctness tests
============================

Asserts the provider -> Common Permission Model mappings the detection
rules depend on. Stdlib `unittest` only.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.common_model import (  # noqa: E402
    CAP_IAM_ADMIN, CAP_IAM_ASSIGN_ROLE, CAP_IAM_CREATE_ROLE, CAP_WILDCARD,
    SERVICES, cap, expand_wildcard, highest_level, is_admin,
)
from src.normalizer import normalize_aws, normalize_azure, normalize_gcp_role  # noqa: E402

ALL_READ = {cap(s, "read") for s in SERVICES}
ESCALATION = {CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE}


def aws(managed=(), docs=()):
    return normalize_aws({"managed_policies": list(managed), "policy_documents": list(docs)})


def policy(*actions, effect="Allow"):
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": list(actions), "Resource": "*"}]}


class TestSuperadminEquivalence(unittest.TestCase):
    """The same 'keys to the kingdom' must normalize identically in all three dialects."""

    def test_admin_roles_expand_to_full_wildcard_set(self):
        full = expand_wildcard()
        self.assertEqual(aws(["AdministratorAccess"]), full)
        self.assertEqual(normalize_azure({"roleDefinitionName": "Owner"}), full)
        self.assertEqual(normalize_gcp_role("roles/owner"), full)
        self.assertIn(CAP_WILDCARD, full)
        self.assertTrue(ESCALATION <= full)
        self.assertTrue(is_admin(full))
        self.assertEqual(highest_level(full), "admin")

    def test_inline_star_action_is_wildcard(self):
        self.assertEqual(aws(docs=[policy("*")]), expand_wildcard())

    def test_azure_star_action_is_wildcard(self):
        self.assertEqual(normalize_azure({"roleDefinitionName": "Custom", "actions": ["*"]}),
                         expand_wildcard())


class TestToxicCombination(unittest.TestCase):
    """create-role + assign-role must be detected however the provider expresses it."""

    def test_aws_inline_policy(self):
        caps = aws(["AmazonS3ReadOnlyAccess"],
                   docs=[policy("iam:CreateRole", "iam:AttachRolePolicy", "iam:PassRole")])
        self.assertTrue(ESCALATION <= caps)
        self.assertNotIn(CAP_WILDCARD, caps)
        self.assertIn(cap("storage", "read"), caps)

    def test_aws_action_matching_is_case_insensitive(self):
        caps = aws(docs=[policy("IAM:createrole", "iam:PASSROLE")])
        self.assertTrue(ESCALATION <= caps)

    def test_azure_custom_role_actions(self):
        caps = normalize_azure({
            "roleDefinitionName": "Custom - Access Deployer",
            "actions": ["Microsoft.Authorization/roleAssignments/write",
                        "Microsoft.Authorization/roleDefinitions/write"]})
        self.assertTrue(ESCALATION <= caps)
        self.assertNotIn(CAP_WILDCARD, caps)

    def test_gcp_two_roles_combine(self):
        a = normalize_gcp_role("roles/iam.roleAdmin")
        b = normalize_gcp_role("roles/iam.serviceAccountTokenCreator")
        self.assertEqual(a, {CAP_IAM_CREATE_ROLE})
        self.assertEqual(b, {CAP_IAM_ASSIGN_ROLE})
        self.assertTrue(ESCALATION <= a | b)

    def test_only_one_half_is_not_toxic(self):
        caps = aws(docs=[policy("iam:PassRole")])
        self.assertIn(CAP_IAM_ASSIGN_ROLE, caps)
        self.assertNotIn(CAP_IAM_CREATE_ROLE, caps)


class TestReadOnlyAndScoped(unittest.TestCase):

    def test_reader_roles_yield_reads_only(self):
        for caps in (aws(["ReadOnlyAccess"]),
                     normalize_azure({"roleDefinitionName": "Reader"}),
                     normalize_gcp_role("roles/viewer")):
            self.assertEqual(caps, ALL_READ)
            self.assertFalse(is_admin(caps))
            self.assertEqual(highest_level(caps), "read")

    def test_scoped_service_grants(self):
        self.assertEqual(aws(["AmazonS3FullAccess"]), {cap("storage", "admin")})
        self.assertEqual(normalize_azure({"roleDefinitionName": "Storage Blob Data Reader"}),
                         {cap("storage", "read")})
        self.assertEqual(normalize_gcp_role("roles/compute.admin"), {cap("compute", "admin")})

    def test_poweruser_is_admin_everywhere_except_iam(self):
        caps = aws(["PowerUserAccess"])
        self.assertIn(cap("compute", "admin"), caps)
        self.assertNotIn(cap("iam", "admin"), caps)
        self.assertNotIn(CAP_IAM_ADMIN, caps)
        self.assertNotIn(CAP_WILDCARD, caps)

    def test_inline_read_actions_are_read_level(self):
        caps = aws(docs=[policy("s3:GetObject", "s3:ListBucket", "logs:GetLogEvents")])
        self.assertEqual(caps, {cap("storage", "read"), cap("logging", "read")})

    def test_deny_statements_are_ignored(self):
        self.assertEqual(aws(docs=[policy("iam:CreateRole", "iam:PassRole", effect="Deny")]), set())

    def test_service_wildcard_on_iam_is_iam_admin(self):
        caps = aws(docs=[policy("iam:*")])
        self.assertIn(CAP_IAM_ADMIN, caps)
        self.assertTrue(ESCALATION <= caps)
        self.assertNotIn(CAP_WILDCARD, caps)


class TestUnknownAndConservative(unittest.TestCase):

    def test_unknown_roles_yield_nothing(self):
        self.assertEqual(aws(["SomeCustomPolicy"]), set())
        self.assertEqual(normalize_azure({"roleDefinitionName": "Custom - Something"}), set())
        self.assertEqual(normalize_gcp_role("roles/weird.unknownRole"), set())

    def test_unknown_mutating_action_is_treated_as_write(self):
        # unknown verb on a known service -> conservative 'write', never dropped
        self.assertEqual(aws(docs=[policy("ec2:TerminateInstances")]), {cap("compute", "write")})

    def test_unknown_service_prefix_is_skipped(self):
        self.assertEqual(aws(docs=[policy("foo:DoThing")]), set())

    def test_common_model_rejects_bad_taxonomy(self):
        with self.assertRaises(ValueError):
            cap("nosuchservice", "read")
        with self.assertRaises(ValueError):
            cap("storage", "root")


if __name__ == "__main__":
    unittest.main(verbosity=2)
