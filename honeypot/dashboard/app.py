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

if df.empty:
    st.info("No interactions logged yet. Start the honeypot and send a few requests.")
    st.stop()


# ---------- KPIs ----------
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total requests", len(df))
col2.metric("Unique attackers", df["fingerprint"].nunique())
col3.metric("Trap hits", int(df["is_trap"].sum()))
col4.metric("Breadcrumb hits", int(df["is_breadcrumb"].sum()))
col5.metric("Honeytoken leaks", len(leaks))


# ---------- Timeline ----------
st.subheader("Activity over time")
df_min = df.set_index("ts").resample("1min").size().rename("requests").reset_index()
fig = px.area(df_min, x="ts", y="requests", title=None)
fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0))
st.plotly_chart(fig, use_container_width=True)


# ---------- Profiles & top endpoints ----------
col_l, col_r = st.columns(2)
with col_l:
    st.subheader("Attacker profiles")
    by_profile = df.groupby("profile").size().reset_index(name="requests")
    st.plotly_chart(px.pie(by_profile, names="profile", values="requests", hole=0.5),
                    use_container_width=True)
with col_r:
    st.subheader("Top hit endpoints")
    top = df.groupby("path").size().reset_index(name="hits").sort_values("hits", ascending=False).head(15)
    st.plotly_chart(px.bar(top, x="hits", y="path", orientation="h"), use_container_width=True)


# ---------- Honeytoken leaks ----------
st.subheader("Honeytoken leaks")
if leaks.empty:
    st.info("No leaks recorded yet.")
else:
    st.dataframe(leaks.sort_values("ts", ascending=False), use_container_width=True, hide_index=True)


# ---------- Live sessions ----------
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


# ---------- Session replay ----------
st.subheader("Session replay")
fp_pick = st.selectbox("Pick an attacker fingerprint", sess["fingerprint"].tolist())
if fp_pick:
    detail = df[df["fingerprint"] == fp_pick].sort_values("ts")
    st.dataframe(
        detail[["ts", "method", "path", "status", "is_trap", "is_breadcrumb",
                "honeytoken_id", "tarpit_delay_ms", "latency_ms", "query", "body"]],
        use_container_width=True, hide_index=True,
    )


# ---------- Blueprint inventory ----------
if bp:
    with st.expander("Deception inventory (traps / honeytokens / breadcrumbs)"):
        st.write("**Traps**")
        st.dataframe(pd.DataFrame([t.model_dump() for t in bp.traps]), use_container_width=True)
        st.write("**Honeytokens**")
        st.dataframe(pd.DataFrame([t.model_dump() for t in bp.honeytokens]), use_container_width=True)
        st.write("**Breadcrumbs**")
        st.dataframe(pd.DataFrame([c.model_dump() for c in bp.breadcrumbs]), use_container_width=True)
