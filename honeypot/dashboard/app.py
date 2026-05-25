"""Streamlit dashboard for the HoneyFP analyst.

Visualises live interactions, attacker profiles, honeytoken leaks,
and the deception blueprint currently deployed.

Run: streamlit run honeypot/dashboard/app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from honeypot.architect.architect import load_blueprint
from honeypot.config import settings


st.set_page_config(page_title="HoneyFP — Analyst Dashboard", layout="wide", page_icon="HP")


# ---------- Data loaders ----------
@st.cache_data(ttl=settings.dashboard_refresh_s)
def load_interactions() -> pd.DataFrame:
    p: Path = settings.interactions_log
    if not p.exists():
        return pd.DataFrame()
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"], unit="s")
    return df


@st.cache_data(ttl=settings.dashboard_refresh_s)
def load_leaks() -> pd.DataFrame:
    p: Path = settings.leak_log
    if not p.exists():
        return pd.DataFrame()
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"], unit="s")
    return df


def load_bp_safe():
    try:
        return load_blueprint()
    except Exception as e:
        st.warning(f"No blueprint loaded yet: {e}")
        return None


# ---------- Layout ----------
st.title("HoneyFP — DAST False Positives turned into a Honeypot")
st.caption("Live view of attacker sessions, honeytoken leaks, and deception inventory.")

bp = load_bp_safe()
df = load_interactions()
leaks = load_leaks()

with st.sidebar:
    st.header("Status")
    if bp:
        st.success(f"Blueprint: {bp.blueprint_id}")
        st.metric("Persona", bp.persona.name)
        st.metric("Traps deployed", len(bp.traps))
        st.metric("Honeytokens", len(bp.honeytokens))
        st.metric("Breadcrumbs", len(bp.breadcrumbs))
    else:
        st.error("No blueprint")
    st.divider()
    if st.button("Refresh now"):
        st.cache_data.clear()
        st.rerun()

# ---------- Strategy lineage tab (always available, even before any traffic) ----------
tab_live, tab_strategies = st.tabs(["Live activity", "Strategies (FP -> Trap lineage)"])

with tab_strategies:
    if not bp:
        st.warning("Generate a blueprint first: `python -m honeypot.run_architect`")
    else:
        fp_path = settings.fp_alerts_path
        if fp_path.exists():
            fps = json.loads(fp_path.read_text(encoding="utf-8"))
            fp_by_id = {a["alert_id"]: a for a in fps}
        else:
            fp_by_id = {}
            st.warning(f"fp_alerts.json not found at {fp_path}")

        st.subheader(f"Persona: {bp.persona.name}  ({bp.persona.industry})")
        st.caption(f"Stack: {', '.join(bp.persona.tech_stack)}  ·  "
                   f"Server header: `{bp.persona.server_header}`  ·  "
                   f"X-Powered-By: `{bp.persona.powered_by}`")

        st.subheader("FP -> Trap lineage")
        st.caption("Each trap below was synthesised by the Architect LLM from one specific "
                   "False Positive classified by the ZAP pipeline.")

        for idx, t in enumerate(bp.traps, 1):
            src = fp_by_id.get(t.source_fp_alert_id, {})
            family_color = {"sql_injection": "#e74c3c", "reflected_xss": "#e67e22",
                            "stored_xss": "#e67e22", "info_disclosure_debug": "#f1c40f",
                            "private_ip_disclosure": "#1abc9c"}.get(t.vuln_family, "#9b59b6")
            with st.expander(f"#{idx}  {t.method} {t.path}  ->  {t.vuln_family}", expanded=(idx <= 2)):
                cols = st.columns([1, 1])
                with cols[0]:
                    st.markdown("**Source False Positive (from ZAP)**")
                    st.markdown(f"""
- alert_id : `{t.source_fp_alert_id}`
- alert_type : {src.get('alert_type', '_(missing)_')}
- endpoint : `{src.get('endpoint', '?')}`
- parameter : `{src.get('parameter') or '(none)'}`
- evidence : `{src.get('evidence', '?')}`
- risk / confidence : {src.get('risk_level', '?')} / {src.get('confidence_level', '?')}
- classifier : {src.get('source', '?')} -> **{src.get('classification', '?')}**
                    """)
                with cols[1]:
                    st.markdown("**Strategy designed by Architect LLM**")
                    st.markdown(f"- vuln_family : `{t.vuln_family}`")
                    st.markdown(f"- triggers : {', '.join(f'`{k}`' for k in t.trigger_keywords) or '_(none)_'}")
                    if t.leaks_honeytoken_id:
                        st.markdown(f"- leaks honeytoken : `{t.leaks_honeytoken_id}`")
                    st.markdown("**Decoy fallback template**")
                    st.code(t.decoy_template, language="text")
                    st.markdown("**Runtime LLM mutation prompt**")
                    st.code(t.llm_mutation_prompt, language="text")

        st.subheader("Honeytokens")
        st.dataframe(pd.DataFrame([h.model_dump() for h in bp.honeytokens]),
                     use_container_width=True, hide_index=True)

        st.subheader("Discovery breadcrumbs")
        st.caption("Multi-hop trail from public files to the leaked SSH creds.")
        for c in bp.breadcrumbs:
            with st.expander(f"{c.kind}  ->  {c.path}", expanded=False):
                st.caption(f"discovery hint: {c.discovery_hint}")
                st.code(c.content, language="text")

        st.subheader("Fake database")
        rows = []
        for tab in bp.fake_db:
            for col in tab.columns:
                rows.append({"table": tab.name, "column": col.name, "sql_type": col.sql_type,
                             "faker_provider": col.faker_provider, "pk": col.primary_key,
                             "row_count": tab.row_count})
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


with tab_live:
    if df.empty:
        st.info("No interactions logged yet. Start the honeypot and send a few requests.")
    else:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total requests", len(df))
        c2.metric("Unique attackers", df["fingerprint"].nunique())
        c3.metric("Trap hits", int(df["is_trap"].sum()))
        c4.metric("Breadcrumb hits", int(df["is_breadcrumb"].sum()))
        c5.metric("Honeytoken leaks", len(leaks))

        st.subheader("Activity over time")
        df_min = df.set_index("ts").resample("1min").size().rename("requests").reset_index()
        fig = px.area(df_min, x="ts", y="requests", title=None)
        fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

        col_l, col_r = st.columns(2)
        with col_l:
            st.subheader("Attacker profiles")
            by_profile = df.groupby("profile").size().reset_index(name="requests")
            st.plotly_chart(px.pie(by_profile, names="profile", values="requests", hole=0.5),
                            use_container_width=True)
        with col_r:
            st.subheader("Top hit endpoints")
            top = (df.groupby("path").size().reset_index(name="hits")
                   .sort_values("hits", ascending=False).head(15))
            st.plotly_chart(px.bar(top, x="hits", y="path", orientation="h"),
                            use_container_width=True)

        st.subheader("Honeytoken leaks")
        if leaks.empty:
            st.info("No leaks recorded yet.")
        else:
            st.dataframe(leaks.sort_values("ts", ascending=False),
                         use_container_width=True, hide_index=True)

        st.subheader("Recent attacker sessions")
        sess = (
            df.groupby("fingerprint")
              .agg(ip=("ip", "first"),
                   profile=("profile", "last"),
                   ua=("user_agent", "first"),
                   requests=("path", "count"),
                   trap_hits=("is_trap", "sum"),
                   breadcrumb_hits=("is_breadcrumb", "sum"),
                   first_seen=("ts", "min"),
                   last_seen=("ts", "max"))
              .reset_index()
              .sort_values("last_seen", ascending=False)
        )
        st.dataframe(sess, use_container_width=True, hide_index=True)

        st.subheader("Session replay")
        fp_pick = st.selectbox("Pick an attacker fingerprint", sess["fingerprint"].tolist())
        if fp_pick:
            detail = df[df["fingerprint"] == fp_pick].sort_values("ts")
            st.dataframe(
                detail[["ts", "method", "path", "status", "is_trap", "is_breadcrumb",
                        "honeytoken_id", "tarpit_delay_ms", "latency_ms", "query", "body"]],
                use_container_width=True, hide_index=True,
            )
