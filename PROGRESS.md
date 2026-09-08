# PROGRESS / HANDOFF — Multi-Cloud Access Governance Dashboard

> **Read this first.** This file is the single source of truth for the current
> state of the project. It is written for the next AI agent (or teammate) to
> pick up work with zero prior context. Last updated: **2026-09-08**.

---

## 1. What this project is

Team **OPSEC** (captain Yahya Dehbi) is competing in the **School of Cyber
Defense 2026** (UAE national competition, organized by DESC / Tech Firm).
This is **Stage 2 – Case**. Our assigned topic (captain-locked, cannot change):

> **Multi-Cloud Access Governance Dashboard** — Difficulty: Intermediate.

### The problem (from the brief)
Government bodies run hybrid estates across several clouds. Permissions drift:
people keep access after changing roles, service accounts outlive their
projects, and nobody has one view of who can do what. Build a dashboard that
ingests permission data from several simulated cloud accounts (AWS/Azure/GCP)
into one model and flags over-privileged users, orphaned accounts, and risky
combinations.

### Minimum deliverable (what they grade)
1. Synthetic but realistic IAM data for **≥3 providers, different native formats**.
2. A **normalizer** mapping provider-specific roles into one common permission model.
3. **Detection rules**: admin/wildcard privileges; unused access (no activity in N days);
   accounts of departed staff; users with the same power across all three clouds;
   toxic combinations (e.g. create-role + assign-role).
4. A **dashboard**: identity list with risk scores, drill-down into *why* an identity
   was flagged, filters by cloud/department.
5. An **exportable findings report** (CSV or PDF).
6. **Demo**: open dashboard on a 500-identity estate, sort by risk, walk through the
   top three findings and the evidence behind each.

---

## 2. CRITICAL submission facts (do not miss)

- **Deliverable uploaded to jury = a PDF**, ≤ 5 pages, ≤ 20.0 MiB, PDF only, passes AV scan.
- **Upload deadline: 11 Sept 2026, 23:59 GST.** Only the **captain** can upload.
- PDF required sections: **Title slide · Project objective · Proposed solution ·
  Solution validation · Results and conclusions**.
- **BUT** the working prototype still matters enormously — see rubric below. The PDF
  must *document/evidence* a real, runnable prototype (screenshots, repo, README).
- If we reach **Top 5** (announced ~14 Sept), there is a **live demo at GISEC, Dubai
  Exhibition Centre, on 18 Sept** — so the prototype must be genuinely demo-able live,
  not faked screenshots.

### Jury scoring rubric (this is what we optimize for)
| Criterion | Weight | How we win it |
|---|---|---|
| Fit to the brief / business problem | 20% | Frame as least-privilege governance for gov hybrid estates; state who deploys it (cloud security / GRC team) and what it replaces (manual quarterly access reviews, siloed per-cloud IAM consoles). |
| Relevance of the proposed solution | 15% | Position vs. current practice: CIEM (Cloud Infrastructure Entitlement Mgmt), Zero-Trust least-privilege, NIST 800-53 AC controls — "why this approach now." |
| **Does the prototype work** | **25%** | Runs end-to-end from README, one command; deterministic; **survives a second run** and **unexpected input**. |
| **Technical depth & correctness** | **25%** | Correct normalization across 3 real IAM formats; defensible, auditable risk model; explainable findings; no logic errors. |
| Innovation | 15% | Cross-cloud "same-power superuser" detection + toxic-combination escalation paths + explainable additive risk score. (Innovation ≠ complexity.) |

---

## 3. Chosen approach & tech stack

- **Language:** Python 3.14 (installed on this machine at
  `C:\Users\NewUser\AppData\Local\Python\pythoncore-3.14-64`). Invoke pip as
  `python -m pip` (bare `pip` is not on PATH).
- **Stack:** **Streamlit** dashboard + **pandas** + **altair** charts + **reportlab** PDF export.
- **Why Streamlit:** best possible score on "runs end-to-end from README" — a single
  `streamlit run app.py`, no frontend build, no DB server, cross-platform. Keeps 100%
  of effort on the governance logic (where the 25% technical-depth marks live).
- **Data model philosophy:** one small, explicit **Common Permission Model (CPM)** —
  capabilities as `service:level` strings + a few sensitive escalation capabilities.
  Small + auditable = hard to get wrong = defensible to a jury.

---

## 4. Project structure & current state

```
school of cyberDefense/
├─ Rules.txt                     # competition rules (topic, rubric, submission) — SOURCE
├─ invite email .txt             # competition invite (dates, structure) — SOURCE
├─ PROGRESS.md                   # THIS FILE
├─ requirements.txt              # streamlit, pandas, altair, reportlab           [DONE]
├─ app.py                        # Streamlit dashboard (UI, filters, drill-down)  [DONE, untested-run]
├─ data/
│  ├─ generate_data.py           # synthetic 500-identity estate generator        [DONE + RUN OK]
│  └─ raw/                        # GENERATED OUTPUT (created by generate_data.py):
│     ├─ hr_directory.csv         #   HR system of record (depts, leavers, SAs)
│     ├─ aws_iam.json             #   AWS native format (per-principal policies)
│     ├─ azure_role_assignments.json  # Azure native format (flat role assignments)
│     ├─ gcp_iam_policy.json      #   GCP native format (role -> members bindings)
│     └─ activity_log.csv         #   unified last-activity signal per principal
└─ src/
   ├─ __init__.py
   ├─ common_model.py            # Common Permission Model / taxonomy               [DONE]
   ├─ normalizer.py              # AWS/Azure/GCP -> CPM mappers                      [DONE]
   ├─ pipeline.py                # load + identity-resolve + normalize -> UnifiedIdentity [DONE + RUN OK]
   ├─ detection.py               # 6 detection rules + additive risk scoring        [DONE + RUN OK]
   └─ report.py                  # CSV + PDF findings export                        [DONE, PDF untested]
```

### What each module does (for quick orientation)
- **`src/common_model.py`** — defines `SERVICES`, `LEVELS`, capability constants
  (`CAP_WILDCARD`, `CAP_IAM_ADMIN`, `CAP_IAM_CREATE_ROLE`, `CAP_IAM_ASSIGN_ROLE`),
  `cap()`, `expand_wildcard()`, `is_admin()`, `highest_level()`.
- **`src/normalizer.py`** — `normalize_aws()`, `normalize_azure()`, `normalize_gcp_role()`.
  Each returns a `set[str]` of normalized capabilities. Conservative (raises modelled
  privilege when unsure — never under-reports risk).
- **`data/generate_data.py`** — deterministic (`SEED=42`, `AS_OF=2026-09-08`). Builds 500
  identities (~430 users + 70 service accounts), places each in 1–3 clouds, and **scripts
  in guaranteed high-risk identities** (3 cross-cloud superusers, 4 departed admins,
  5 toxic-combo, 6 orphaned SAs) so the demo top findings are guaranteed + explainable.
  Writes 5 native-format files to `data/raw/`.
- **`src/pipeline.py`** — `build_identities()` returns `(list[UnifiedIdentity], ref_date)`.
  Join key = corporate email. **Identity resolution bridge:** `activity_log.csv` maps GCP
  `type:email` member strings back to canonical email (AWS/Azure carry email directly).
  Defensive parsing (missing files, bad dates, unknown principals) for the "unexpected
  input" score. `UnifiedIdentity` has `.all_capabilities`, `.providers`, `.last_activity`.
- **`src/detection.py`** — `analyze(identities, ref, cfg)` → list of result dicts sorted by
  risk desc. 6 rules, each producing a `Finding(rule_id, title, weight, evidence,
  remediation, severity)`. Additive capped 0–100 risk score. `DetectionConfig.unused_days`
  (default 90) is configurable.
- **`src/report.py`** — `findings_to_csv()`, `summary_csv()`, `findings_to_pdf()` (reportlab).
- **`app.py`** — Streamlit UI: KPI metrics, 3 altair charts (severity / by-rule /
  by-department), risk-sorted identity table with progress-bar column, drill-down panel
  (per-cloud presence + native roles + normalized caps + findings with evidence &
  remediation), sidebar filters (cloud, department, severity, search, unused-days slider,
  only-flagged), and CSV/CSV/PDF export buttons. Uses `@st.cache_data`.

### Detection rules & weights (in `detection.py`)
| rule_id | weight | fires when |
|---|---|---|
| `departed_staff` | 40 | HR status = departed but still holds cloud access |
| `cross_cloud_superuser` | 30 | admin-grade access in ≥3 clouds (`cross_cloud_min`) |
| `toxic_combination` | 25 | holds both `iam:create_role` AND `iam:assign_role` |
| `admin_wildcard` | 20 | holds `wildcard` (`*`) OR `iam:admin` (keys-to-the-kingdom only) |
| `orphaned_service_account` | 15 | service account, no human owner, idle ≥ N days |
| `unused_access` | 10 | no activity in ≥ N days (default 90) |

Severity bands: score ≥70 Critical, ≥40 High, ≥20 Medium, >0 Low, 0 None.

---

## 5. Verified results so far (already run successfully)

- `python data/generate_data.py` → 500 identities; 359 AWS principals, 382 Azure
  assignments, 532 GCP binding members. Files written to `data/raw/`. ✅
- `python -m src.pipeline` → "Resolved 500 identities with cloud access"; 177 present
  in all 3 clouds. ✅
- `python -m src.detection` → 130 flagged; severity {Critical 7, High 31, Medium 25,
  Low 67, None 370}; findings by rule {departed_staff 35, cross_cloud_superuser 5,
  toxic_combination 12, admin_wildcard 7, unused_access 100, orphaned_service_account 20}. ✅
  - **Top-3 demo identities** (deterministic): Huda Qureshi (100, Engineering),
    Noah Osman (100, Operations), Layla Al Balushi (95, Security) — each triggers a rich
    mix of rules with full evidence.

**Design refinement already applied:** `admin_wildcard` originally fired on any
single-service admin (334 hits — too noisy). Tightened to only `wildcard`/`iam:admin`
("keys to the kingdom") → 7 hits, precise + defensible. See comment in `detection.py`
Rule 4.

---

## 6. WHAT IS LEFT TO DO (next steps, in priority order)

### ⛔ BLOCKER encountered
Installing dependencies was **interrupted/declined by the user**. The command was:
```
python -m pip install -r requirements.txt
```
**Next agent: ask the user before running installs.** They may prefer a virtualenv,
`--user`, or to run it themselves. Nothing below can be runtime-verified until deps
(streamlit, pandas, altair, reportlab) are installed. All *logic* modules
(generate/pipeline/detection) already run on the **stdlib only** and are verified.

### Task list (mirrors the in-tool task tracker)
1. ~~Build synthetic data generator~~ ✅ done
2. ~~Build normalizer~~ ✅ done
3. ~~Build detection engine + risk scoring~~ ✅ done
4. **Build Streamlit dashboard** — code written (`app.py`); **needs a real run** once
   deps installed (`streamlit run app.py`). Verify charts, table, drill-down, filters.
5. ~~Add CSV/PDF export~~ ✅ code written; **PDF path (`findings_to_pdf`) not yet executed** —
   test it (reportlab). CSV path is stdlib, low risk.
6. **Write README + the 5-page PDF submission** — NOT STARTED. This is the graded artifact.

### Concrete remaining work
- [ ] **Install deps** (get user consent): `python -m pip install -r requirements.txt`.
- [ ] **Run & smoke-test the app**: `streamlit run app.py`. Confirm it loads the 500-identity
      estate, sorts by risk, drill-down shows evidence, filters work, all 3 exports download.
- [ ] **Test resilience** (for the 25% "survives second run + unexpected input" score):
      run generator twice (must be identical), delete/corrupt a raw file and confirm the app
      degrades gracefully (loaders already default-safe), feed a malformed date.
- [ ] **Write `README.md`** — one-command quickstart:
      `python -m pip install -r requirements.txt` → `python data/generate_data.py`
      → `streamlit run app.py`. Include architecture diagram, rule table, screenshots.
- [ ] **Write the 5-page PDF** (the actual submission). Suggested page plan:
      1. **Title** — project name, Team OPSEC, members, competition, date.
      2. **Project objective** — the business problem (permission drift in gov hybrid
         estates), who deploys it, what it replaces (manual reviews / siloed consoles).
      3. **Proposed solution** — architecture (ingest → normalize to CPM → detect → score →
         dashboard/export), the 3 native formats, the common model, the 6 rules; position
         vs. CIEM / Zero-Trust / NIST 800-53 AC ("why now").
      4. **Solution validation** — how it runs from README; determinism; the 500-identity
         run stats; screenshots of dashboard + a top-3 drill-down with evidence; resilience
         tests. This is where the 25% prototype + 25% depth marks are evidenced.
      5. **Results & conclusions** — the numbers (130 flagged, 7 critical, rule breakdown),
         top-3 walkthrough, remediation value, limitations & next steps.
      - Generate the PDF from the content (could reuse reportlab, or export from
        Slides/Canva/LaTeX). Keep ≤ 5 pages, ≤ 20 MiB. **Only captain Yahya uploads.**
- [ ] Capture demo screenshots for the PDF.
- [ ] (Optional, if time) small unit tests for the normalizer mappings to bolster
      "technical correctness."
- [ ] (If Top 5) prepare a tight live-demo script for GISEC 18 Sept.

---

## 7. Schedule (deadline 11 Sept 23:59 GST)

| Day | Plan |
|---|---|
| **Day 1 – 8 Sept (done)** | Data generator → normalizer → detection → risk scoring. ✅ All built & verified on stdlib. Dashboard + export code written. |
| **Day 2 – 9 Sept** | Install deps; run & polish Streamlit app; PDF-export test; resilience tests; capture screenshots; write README. |
| **Day 3 – 10 Sept** | Write & design the 5-page PDF mapped 1:1 to the rubric; internal review; buffer. |
| **11 Sept** | Final polish; **captain uploads the PDF** before 23:59 GST. |

---

## 8. Key facts / gotchas for the next agent

- **Run commands from the project root** so `from src....` imports resolve. Modules are
  run as `python -m src.pipeline` / `python -m src.detection` (not by file path).
- **Windows + PowerShell** environment. Use `python -m pip`, not `pip`.
- **Determinism** is a feature, not incidental — `SEED=42`, `AS_OF=2026-09-08` in
  `generate_data.py`. The reference "today" used by detection comes from the AWS export's
  `GeneratedAt` field (see `pipeline.reference_date`), so re-runs are reproducible.
- **Do not change the topic** — it is captain-locked to Multi-Cloud Access Governance.
- **The PDF is the graded artifact**, but it must faithfully evidence the working prototype.
  Don't over-invest in code polish at the expense of the 5-page PDF.
- Team members / captain and org details are in `Rules.txt`; dates in `invite email .txt`.
- Organizer site: https://scd.techfirm.ae/ (little extra detail beyond the txt files).

---

## 9. One-command run (target for README)

```bash
python -m pip install -r requirements.txt
python data/generate_data.py       # writes data/raw/*  (deterministic)
streamlit run app.py               # open the dashboard
```
Individual logic checks (no external deps needed):
```bash
python -m src.pipeline             # identity resolution stats
python -m src.detection            # analysis + top-5 by risk
```
