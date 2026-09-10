"""
Resilience + determinism tests
==============================

Evidence for the "prototype works: survives a second run and unexpected
input" criterion. Stdlib `unittest` only, no extra dependencies.

Run from the project root:

    python -m unittest discover -s tests -v

Every corrupted fixture is built in a temporary directory; `data/raw/` is
never touched.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
sys.path.insert(0, ROOT)

from src.detection import DetectionConfig, analyze  # noqa: E402
from src.pipeline import build_identities  # noqa: E402

RAW_FILES = [
    "hr_directory.csv", "aws_iam.json", "azure_role_assignments.json",
    "gcp_iam_policy.json", "activity_log.csv",
]


def _run(raw_dir: str):
    identities, ref = build_identities(raw_dir)
    results = analyze(identities, ref, DetectionConfig())
    flagged = [r for r in results if r["risk_score"] > 0]
    return identities, results, flagged


def _hashes(directory: str) -> dict[str, str]:
    out = {}
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), "rb") as f:
            # normalise line endings so a Linux/macOS run matches files committed from Windows
            out[name] = hashlib.sha256(f.read().replace(b"
", b"
")).hexdigest()
    return out


class ScratchEstate(unittest.TestCase):
    """Copies the generated estate into a temp dir so tests can corrupt it."""

    def setUp(self):
        self.assertTrue(os.path.exists(os.path.join(RAW, "aws_iam.json")),
                        "run `python data/generate_data.py` first")
        self.tmp = tempfile.mkdtemp(prefix="mcagd-")
        self.raw = os.path.join(self.tmp, "raw")
        shutil.copytree(RAW, self.raw)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _json(self, name):
        with open(os.path.join(self.raw, name), encoding="utf-8") as f:
            return json.load(f)

    def _write_json(self, name, obj):
        with open(os.path.join(self.raw, name), "w", encoding="utf-8") as f:
            json.dump(obj, f)

    def _write_text(self, name, text, mode="w"):
        with open(os.path.join(self.raw, name), mode, encoding="utf-8", newline="") as f:
            f.write(text)


class TestBaseline(ScratchEstate):

    def test_full_estate_produces_expected_shape(self):
        identities, results, flagged = _run(self.raw)
        self.assertEqual(len(identities), 500)
        self.assertEqual(len(results), 500)
        self.assertGreater(len(flagged), 0)
        # sorted by risk, descending
        scores = [r["risk_score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))
        # every finding carries evidence + remediation (explainability)
        for r in flagged:
            for f in r["findings"]:
                self.assertTrue(f.evidence and f.remediation, f.rule_id)


class TestDeterminism(unittest.TestCase):

    def test_generator_is_byte_for_byte_reproducible(self):
        """Second run must be identical (scored requirement)."""
        tmp = tempfile.mkdtemp(prefix="mcagd-gen-")
        try:
            env = dict(os.environ)
            runs = []
            for i in (1, 2):
                out = os.path.join(tmp, f"run{i}")
                os.makedirs(out)
                # generate_data.py writes next to itself; run a copy inside tmp
                gen_dir = os.path.join(out, "data")
                os.makedirs(gen_dir)
                shutil.copy(os.path.join(ROOT, "data", "generate_data.py"), gen_dir)
                subprocess.run([sys.executable, os.path.join(gen_dir, "generate_data.py")],
                               check=True, capture_output=True, env=env, cwd=out)
                runs.append(_hashes(os.path.join(gen_dir, "raw")))
            self.assertEqual(runs[0], runs[1])
            self.assertEqual(sorted(runs[0]), sorted(RAW_FILES))
            # ...and identical to what is committed in data/raw
            self.assertEqual(runs[0], _hashes(RAW))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestMissingInput(ScratchEstate):

    def test_missing_provider_export_degrades_gracefully(self):
        os.remove(os.path.join(self.raw, "azure_role_assignments.json"))
        identities, results, flagged = _run(self.raw)
        providers = {p for r in results for p in r["providers"]}
        self.assertEqual(providers, {"aws", "gcp"})
        self.assertGreater(len(flagged), 0)

    def test_missing_hr_directory_marks_everyone_unmanaged(self):
        os.remove(os.path.join(self.raw, "hr_directory.csv"))
        identities, results, flagged = _run(self.raw)
        self.assertGreater(len(identities), 0)
        self.assertTrue(all(i.department == "Unmanaged" for i in identities))

    def test_missing_activity_log_still_runs(self):
        os.remove(os.path.join(self.raw, "activity_log.csv"))
        identities, results, flagged = _run(self.raw)
        self.assertGreater(len(identities), 0)

    def test_empty_directory_yields_empty_estate(self):
        for name in RAW_FILES:
            os.remove(os.path.join(self.raw, name))
        identities, results, flagged = _run(self.raw)
        self.assertEqual(identities, [])
        self.assertEqual(results, [])


class TestCorruptInput(ScratchEstate):

    def test_invalid_json_and_empty_csv(self):
        self._write_text("gcp_iam_policy.json", "{not json")
        self._write_text("hr_directory.csv", "")
        identities, results, flagged = _run(self.raw)
        self.assertGreater(len(identities), 0)
        self.assertNotIn("gcp", {p for r in results for p in r["providers"]})

    def test_json_with_wrong_top_level_type(self):
        self._write_json("aws_iam.json", ["not", "an", "object"])
        self._write_json("azure_role_assignments.json", None)
        self._write_json("gcp_iam_policy.json", 42)
        identities, results, flagged = _run(self.raw)
        self.assertEqual(identities, [])  # HR only -> nobody holds cloud access

    def test_wrong_typed_fields_do_not_crash(self):
        aws = self._json("aws_iam.json")
        p = aws["Principals"]
        p[0]["LastActivity"] = "not-a-date"
        p[1]["AttachedManagedPolicies"] = "garbage"          # str instead of list
        p[2].pop("Email")                                     # missing join key
        p[3]["AttachedManagedPolicies"] = [None, 7, "PowerUserAccess"]
        p[4]["InlinePolicyDocuments"] = ["x", {"Statement": "bad"},
                                         {"Statement": [{"Effect": "Allow", "Action": 5}]}]
        p[5]["Email"] = 12345
        p.append("not a principal")
        p.append({"Email": "loose@gov.ae", "AttachedManagedPolicies": {"PolicyName": "ReadOnlyAccess"}})
        aws["GeneratedAt"] = "31/12/2026"                     # unparseable -> today
        self._write_json("aws_iam.json", aws)

        az = self._json("azure_role_assignments.json")
        a = az["roleAssignments"]
        a[0]["actions"] = "Microsoft.Authorization/roleAssignments/write"  # str not list
        a[1]["actions"] = [None, {"x": 1}]
        a[2]["roleDefinitionName"] = None
        a[3]["principalEmail"] = ["list"]
        a.append(None)
        self._write_json("azure_role_assignments.json", az)

        gcp = self._json("gcp_iam_policy.json")
        gcp["bindings"].append({"role": "roles/weird.unknownRole",
                                "members": ["group:admins@gov.ae",
                                            "deleted:user:x@gov.ae?uid=1", None, ""]})
        gcp["bindings"].append({"role": None, "members": "user:str@gov.ae"})
        gcp["bindings"].append("junk")
        self._write_json("gcp_iam_policy.json", gcp)

        self._write_text("activity_log.csv",
                         "aws,arn:unknown,nobody@nowhere,2026-99-99\n,,,\nonly-one-column\n",
                         mode="a")

        with open(os.path.join(self.raw, "hr_directory.csv"), encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        rows[0]["termination_date"] = "yesterday"
        rows[1]["is_service_account"] = "maybe"
        rows[2]["email"] = ""
        rows[3]["status"] = "DEPARTED"
        with open(os.path.join(self.raw, "hr_directory.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

        identities, results, flagged = _run(self.raw)
        self.assertGreater(len(identities), 400)
        self.assertGreater(len(flagged), 0)
        by_email = {i.email: i for i in identities}
        self.assertIn("loose@gov.ae", by_email)               # dict-not-list policy accepted
        self.assertIn("storage:read", by_email["loose@gov.ae"].all_capabilities)
        self.assertEqual(by_email[rows[3]["email"].lower()].status, "departed")

    def test_non_utf8_file_is_treated_as_missing(self):
        with open(os.path.join(self.raw, "hr_directory.csv"), "wb") as f:
            f.write(b"\xff\xfe\x00garbage\x00\xff")
        identities, results, flagged = _run(self.raw)
        self.assertGreater(len(identities), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
