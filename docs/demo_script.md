# Live demo script (5 minutes)

For the GISEC Top-5 stage on 18 Sept, or any walkthrough. Everything below is
deterministic: the same identities, scores and numbers appear on every run.

## Before you start

```bash
python -m unittest discover -s tests          # 32 tests, ~5 s: proves the estate + app are healthy
streamlit run app.py                          # http://localhost:8501
```

Keep the sidebar at defaults: window 90 days, all clouds, all departments,
all severities, "Only show flagged" ticked.

## 0:00 The problem (30 s)

"Three clouds, three consoles, one organisation. Nobody can answer *who can do
what* across all of them, so permissions drift: leavers keep access, service
accounts outlive their projects, one person quietly becomes admin everywhere."

## 0:30 One model, one view (45 s)

Point at the KPI strip: **500 identities, 130 flagged, 7 Critical, 5
cross-cloud superusers, 35 leavers still holding access.**

Point at the three charts. "Every number here comes from three *native*
exports: AWS policy JSON, Azure role assignments, GCP bindings. They are
normalized into one small permission model (eight services, three levels,
four escalation capabilities) so the rules only have to be written once."

## 1:15 Top finding: Huda Qureshi, 100 (75 s)

The drill-down opens on her by default.

1. **HR status: departed, terminated 2026-04-03. Still has access in all three clouds.**
2. **Score breakdown**: 40 + 30 + 25 + 20 + 10 = 125, capped at 100. "Additive, so
   a jury can re-derive it by hand. Nothing is a black box."
3. **Capability matrix**: solid red. Admin on every service in every cloud.
   "This is what AdministratorAccess, Owner and roles/owner look like once
   normalized: identical, which is the point."
4. Scroll to **Findings**: read the first evidence line and its remediation.
   "One deprovisioning action closes five findings."

## 2:30 Second and third findings (60 s)

Select **Noah Osman (100)**: same pattern, Operations. "Two leavers with
estate-wide admin is not a coincidence, it is a process gap: offboarding
never reached the clouds."

Select **Layla Al Balushi (95)**: GCP only, but *roles/owner* plus the
create-role + assign-role escalation path. "Even in a single cloud, the
combination matters more than any one role."

## 3:30 Filters and the window (45 s)

- Drag **Unused-access window** to 150 days: flagged drops 130 -> 109, the
  "unused access" finding text changes to 150+ days. "Policy language, not a
  hard-coded number."
- Remove **AWS** from the cloud filter: 125 shown. Type **osman** in search:
  the list and the drill-down follow.

## 4:15 Export and close (45 s)

Click **Executive report (PDF)**: the same evidence as an auditor-ready
document; the CSVs are the machine-readable trail.

"It runs from a README in three commands, on any laptop, with no cloud
credentials. It survived every malformed input we threw at it, which is
tested, not claimed. The next step is real exports and snapshot diffing."

## If asked

- **Why additive scoring?** Auditable. A weighted or ML score cannot be
  explained to a department head in one sentence.
- **Why so few rules?** Precision. `admin_wildcard` originally fired on any
  single-service admin (334 hits); tightening it to wildcard / iam:admin gave
  7 precise hits. Innovation is precision, not complexity.
- **What about custom roles?** Unknown roles map to no capability and stay
  visible as native roles in the drill-down, so they are never silently
  ignored; parsing custom-role definitions is the next step.
- **Real data?** Replace `data/raw/` with IAM Access Analyzer, Azure Resource
  Graph and `gcloud projects get-iam-policy` exports; only the mapping tables
  in `src/normalizer.py` need extending.
