"""
Multi-Cloud Access Governance Dashboard
=======================================

Streamlit front end. Run with:

    streamlit run app.py

One view of "who can do what" across AWS, Azure and GCP, with risk scoring,
drill-down evidence, filters and exportable findings.
"""

from __future__ import annotations

import os
from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

from src.common_model import (CAP_IAM_ADMIN, CAP_IAM_ASSIGN_ROLE, CAP_IAM_CREATE_ROLE,
                              CAP_WILDCARD, LEVELS, SERVICES)
from src.detection import DetectionConfig, WEIGHTS, analyze
from src.pipeline import build_identities
from src.report import findings_to_csv, findings_to_pdf, summary_csv

RAW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "raw")

SEVERITY_COLORS = {
    "Critical": "#b91c1c", "High": "#ea580c",
    "Medium": "#ca8a04", "Low": "#2563eb", "None": "#6b7280",
}

st.set_page_config(page_title="Multi-Cloud Access Governance",
                   page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner=False)
def load_base():
    """Load + normalize the estate once (independent of detection config)."""
    identities, ref = build_identities(RAW)
    return identities, ref


@st.cache_data(show_spinner=False)
def run_analysis(unused_days: int):
    identities, ref = load_base()
    cfg = DetectionConfig(unused_days=unused_days)
    return analyze(identities, ref, cfg), ref


def severity_badge(sev: str) -> str:
    return f":{'red' if sev in ('Critical', 'High') else 'orange' if sev == 'Medium' else 'blue'}[{sev}]"


LEVEL_COLORS = {"admin": "#b91c1c", "write": "#c2410c", "read": "#1d4ed8", "none": ""}
ESCALATION_CAPS = (CAP_WILDCARD, CAP_IAM_ADMIN, CAP_IAM_CREATE_ROLE, CAP_IAM_ASSIGN_ROLE)


def capability_matrix(ident) -> pd.DataFrame:
    """Service x cloud grid of the highest normalized level held in each cloud."""
    rows = {}
    for svc in SERVICES:
        row = {}
        for prov in ident.providers:
            caps = ident.clouds[prov].capabilities
            level = "none"
            if CAP_WILDCARD in caps:
                level = "admin"
            else:
                for lvl in LEVELS:                      # read < write < admin
                    if f"{svc}:{lvl}" in caps:
                        level = lvl
            row[prov.upper()] = level
        rows[svc] = row
    return pd.DataFrame(rows).T


def _level_style(v: str) -> str:
    c = LEVEL_COLORS.get(v, "")
    return f"background-color: {c}; color: white; font-weight: 600" if c else "color: #6b7280"


def score_breakdown_chart(findings) -> alt.Chart:
    """Additive score made visible: every rule, points added (0 if not triggered)."""
    got = {f.rule_id: f.weight for f in findings}
    df = pd.DataFrame([{
        "Rule": k.replace("_", " "), "Points": got.get(k, 0), "Max": v,
        "Status": "triggered" if k in got else "not triggered",
    } for k, v in WEIGHTS.items()])
    order = [k.replace("_", " ") for k in WEIGHTS]
    base = alt.Chart(df).encode(y=alt.Y("Rule", sort=order, title=None,
                                        axis=alt.Axis(labelOverlap=False, labelLimit=160)))
    ghost = base.mark_bar(color="#374151", opacity=0.35).encode(
        x=alt.X("Max", scale=alt.Scale(domain=[0, 40]), title="points added to risk score"))
    bars = base.mark_bar().encode(
        x="Points",
        color=alt.Color("Status", scale=alt.Scale(domain=["triggered", "not triggered"],
                                                  range=["#b91c1c", "#374151"]), legend=None),
        tooltip=["Rule", "Points", "Max", "Status"])
    return (ghost + bars).properties(height=190)


# ---------------------------------------------------------------------------
# Data checks / bootstrap
# ---------------------------------------------------------------------------
if not os.path.exists(os.path.join(RAW, "aws_iam.json")):
    st.error("No estate data found. Run `python data/generate_data.py` first.")
    st.stop()

# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ Access Governance")
st.sidebar.caption("Team OPSEC · School of Cyber Defense 2026")

unused_days = st.sidebar.slider(
    "Unused-access window (days)", min_value=30, max_value=180, value=90, step=15,
    help="Flag identities with no activity in the last N days.")

results, ref = run_analysis(unused_days)
df = pd.DataFrame([{
    "Risk": r["risk_score"], "Severity": r["severity"], "Name": r["name"],
    "Email": r["email"], "Department": r["department"], "Status": r["status"],
    "Type": "Service" if r["is_service_account"] else "User",
    "Clouds": ", ".join(p.upper() for p in r["providers"]),
    "Findings": r["finding_count"],
} for r in results])

all_providers = sorted({p for r in results for p in r["providers"]})
all_depts = sorted({r["department"] for r in results})

sel_providers = st.sidebar.multiselect("Cloud", all_providers, default=all_providers)
sel_depts = st.sidebar.multiselect("Department", all_depts, default=all_depts)
sel_sev = st.sidebar.multiselect(
    "Severity", ["Critical", "High", "Medium", "Low", "None"],
    default=["Critical", "High", "Medium", "Low", "None"])
search = st.sidebar.text_input("Search name / email").strip().lower()
only_flagged = st.sidebar.checkbox("Only show flagged identities", value=True)


def visible(r: dict) -> bool:
    if not (set(r["providers"]) & set(sel_providers)):
        return False
    if r["department"] not in sel_depts:
        return False
    if r["severity"] not in sel_sev:
        return False
    if only_flagged and r["risk_score"] == 0:
        return False
    if search and search not in r["name"].lower() and search not in r["email"].lower():
        return False
    return True


filtered = [r for r in results if visible(r)]

# ---------------------------------------------------------------------------
# Header + KPIs
# ---------------------------------------------------------------------------
st.title("Multi-Cloud Access Governance Dashboard")
st.caption(f"One identity model across AWS · Azure · GCP — estate snapshot as of **{ref.isoformat()}**")

flagged = [r for r in results if r["risk_score"] > 0]
sev_counts = Counter(r["severity"] for r in results)
cross_cloud = sum(1 for r in results if any(f.rule_id == "cross_cloud_superuser" for f in r["findings"]))
departed = sum(1 for r in results if any(f.rule_id == "departed_staff" for f in r["findings"]))

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Identities", len(results))
c2.metric("Flagged", len(flagged))
c3.metric("Critical", sev_counts.get("Critical", 0))
c4.metric("High", sev_counts.get("High", 0))
c5.metric("Cross-cloud superusers", cross_cloud)
c6.metric("Departed w/ access", departed)

st.divider()

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
ch1, ch2, ch3 = st.columns(3)

with ch1:
    st.subheader("Risk by severity")
    sev_df = pd.DataFrame(
        [{"Severity": s, "Count": sev_counts.get(s, 0)}
         for s in ["Critical", "High", "Medium", "Low", "None"]])
    chart = alt.Chart(sev_df).mark_bar().encode(
        x=alt.X("Severity", sort=["Critical", "High", "Medium", "Low", "None"]),
        y="Count",
        color=alt.Color("Severity", scale=alt.Scale(
            domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values())),
            legend=None),
    ).properties(height=240)
    st.altair_chart(chart, width="stretch")

with ch2:
    st.subheader("Findings by rule")
    rule_counts = Counter(f.rule_id for r in results for f in r["findings"])
    rule_df = pd.DataFrame(
        [{"Rule": k.replace("_", " "), "Count": v} for k, v in rule_counts.items()]
    ).sort_values("Count", ascending=False)
    chart = alt.Chart(rule_df).mark_bar(color="#2563eb").encode(
        x="Count", y=alt.Y("Rule", sort="-x")).properties(height=240)
    st.altair_chart(chart, width="stretch")

with ch3:
    st.subheader("Risk exposure by department")
    dept_df = pd.DataFrame([
        {"Department": d,
         "Risk": sum(r["risk_score"] for r in results if r["department"] == d)}
        for d in all_depts]).sort_values("Risk", ascending=False).head(8)
    chart = alt.Chart(dept_df).mark_bar(color="#b91c1c").encode(
        x="Risk", y=alt.Y("Department", sort="-x")).properties(height=240)
    st.altair_chart(chart, width="stretch")

st.divider()

# ---------------------------------------------------------------------------
# Identity list + drill-down
# ---------------------------------------------------------------------------
left, right = st.columns([1.4, 1])

with left:
    st.subheader(f"Identities · risk-sorted ({len(filtered)} shown)")
    fdf = pd.DataFrame([{
        "Risk": r["risk_score"], "Severity": r["severity"], "Name": r["name"],
        "Department": r["department"], "Type": "Service" if r["is_service_account"] else "User",
        "Clouds": ", ".join(p.upper() for p in r["providers"]),
        "Findings": r["finding_count"], "Email": r["email"],
    } for r in filtered])
    if fdf.empty:
        st.info("No identities match the current filters.")
    else:
        st.dataframe(
            fdf, width="stretch", hide_index=True, height=460,
            column_config={
                "Risk": st.column_config.ProgressColumn(
                    "Risk", min_value=0, max_value=100, format="%d"),
            })

with right:
    st.subheader("Drill-down: why was this flagged?")
    options = {f"{r['risk_score']:3d} · {r['name']} ({r['email']})": r for r in filtered}
    if options:
        pick = st.selectbox("Select an identity", list(options.keys()))
        r = options[pick]
        st.markdown(f"### {r['name']}  {severity_badge(r['severity'])}")
        st.write(f"**Risk score:** {r['risk_score']}/100  ·  "
                 f"**{r['title'] or 'Service Account'}** — {r['department']}")
        st.write(f"**Email:** `{r['email']}`  ·  **HR status:** {r['status']}")
        if r["days_inactive"] is not None:
            st.write(f"**Last activity:** {r['last_activity']} ({r['days_inactive']} days ago)")
        ident = r["_identity"]

        st.markdown("**Score breakdown** · additive weights, capped at 100")
        st.altair_chart(score_breakdown_chart(r["findings"]), width="stretch")
        raw_sum = sum(f.weight for f in r["findings"])
        if raw_sum:
            st.caption(" + ".join(str(f.weight) for f in r["findings"]) + f" = {raw_sum}"
                       + (f" → capped at 100" if raw_sum > 100 else ""))
        else:
            st.caption("No rule triggered → 0.")

        st.markdown("**Capability matrix** · highest normalized level per service and cloud")
        matrix = capability_matrix(ident)
        st.dataframe(matrix.style.map(_level_style), width="stretch",
                     height=min(36 + 35 * len(matrix), 330))
        esc = {prov.upper(): [c for c in ESCALATION_CAPS if c in ident.clouds[prov].capabilities]
               for prov in ident.providers}
        if any(esc.values()):
            st.caption("Escalation capabilities: " + " · ".join(
                f"{p}: {', '.join(f'`{c}`' for c in cs)}" for p, cs in esc.items() if cs))
        else:
            st.caption("No escalation capabilities (wildcard / iam:admin / create-role / assign-role).")

        st.markdown("**Cloud presence & native roles**")
        for prov in ident.providers:
            p = ident.clouds[prov]
            with st.expander(f"{prov.upper()} — {p.principal_type}", expanded=False):
                st.caption(f"principal: `{p.principal_ref}`")
                st.write("Native roles/policies: " +
                         (", ".join(p.native_roles) or "—"))
                st.write("Normalized: " + (", ".join(f"`{c}`" for c in sorted(p.capabilities)) or "—"))

        st.markdown("**Findings**")
        if not r["findings"]:
            st.success("No governance findings for this identity.")
        for f in r["findings"]:
            st.markdown(f"**{severity_badge(f.severity)} {f.title}** _(+{f.weight})_")
            st.write(f"🔎 {f.evidence}")
            st.write(f"✅ *Remediation:* {f.remediation}")

st.divider()

# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
st.subheader("Export findings report")
e1, e2, e3 = st.columns(3)
e1.download_button(
    "⬇️ Findings (CSV)", data=findings_to_csv(filtered),
    file_name="access_findings.csv", mime="text/csv", width="stretch")
e2.download_button(
    "⬇️ Identity summary (CSV)", data=summary_csv(filtered),
    file_name="identity_summary.csv", mime="text/csv", width="stretch")
try:
    e3.download_button(
        "⬇️ Executive report (PDF)", data=findings_to_pdf(filtered, ref),
        file_name="access_governance_report.pdf", mime="application/pdf",
        width="stretch")
except Exception as exc:  # reportlab optional at runtime
    e3.info(f"PDF export unavailable: {exc}")

st.caption("Multi-Cloud Access Governance Dashboard · Team OPSEC · "
           "detection weights: " +
           ", ".join(f"{k}={v}" for k, v in WEIGHTS.items()))
