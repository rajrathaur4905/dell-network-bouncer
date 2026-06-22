import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

try:
    from src.dashboard.report_processing import (
        apply_severity_filter,
        normalize_report,
        summarize_report,
    )
except ModuleNotFoundError:
    from report_processing import (
        apply_severity_filter,
        normalize_report,
        summarize_report,
    )

st.set_page_config(page_title="Network Bouncer", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    [data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #21262d; }
    .metric-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; text-align: center; }
    .metric-card.red { border-left: 4px solid #f85149; }
    .metric-card.green { border-left: 4px solid #3fb950; }
    .metric-card.yellow { border-left: 4px solid #d29922; }
    .metric-card.blue { border-left: 4px solid #388bfd; }
    .metric-value { font-size: 2rem; font-weight: 700; font-family: monospace; }
    .metric-label { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
    .section-title { font-size: 1rem; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: 2px; border-bottom: 1px solid #21262d; padding-bottom: 8px; margin: 24px 0 16px 0; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style='padding: 24px 0 8px 0;'>
    <span style='font-size:2rem; font-weight:800; font-family:monospace; color:#f0f6fc;'>🛡️ NETWORK BOUNCER</span><br>
    <span style='color:#8b949e; font-size:0.9rem; letter-spacing:2px;'>SUSPICIOUS PORT SCAN DETECTION — DASHBOARD</span>
</div>
<hr style='border-color:#21262d; margin-bottom:24px;'>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 📂 Load Report")
    uploaded = st.file_uploader("Upload CSV", type=["csv"], label_visibility="collapsed")
    st.markdown("---")
    st.markdown("### 🔧 Filter Options")
    severity_filter = st.multiselect(
        "Filter by Severity",
        options=["HIGH", "MEDIUM", "LOW"],
        default=["HIGH", "MEDIUM", "LOW"]
    )
    st.markdown("---")
    st.markdown("<span style='color:#8b949e; font-size:0.75rem;'>Network Bouncer v1.0<br>Dell Hackathon 2026</span>", unsafe_allow_html=True)

# ── Load data ─────────────────────────────────────────────────────────────────
if uploaded:
    df = normalize_report(pd.read_csv(uploaded))
    st.success(f"✅ Loaded `{uploaded.name}` — {len(df)} records")
else:
    st.warning("⬅️ Upload your suspicious_activity_report.csv from the sidebar.")
    st.stop()

# ── Apply severity filter (case-insensitive) ──────────────────────────────────
df = apply_severity_filter(df, severity_filter)

# ── Split suspicious vs normal (case-insensitive) ─────────────────────────────
summary = summarize_report(df)
suspicious_df = summary.suspicious_df

# ── KPI Cards ─────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"<div class='metric-card blue'><div class='metric-value'>{summary.total_alerts}</div><div class='metric-label'>Total Alerts</div></div>", unsafe_allow_html=True)
with c2:
    st.markdown(f"<div class='metric-card red'><div class='metric-value'>{summary.high_risk_count}</div><div class='metric-label'>High Risk</div></div>", unsafe_allow_html=True)
with c3:
    st.markdown(f"<div class='metric-card yellow'><div class='metric-value'>{summary.suspicious_count}</div><div class='metric-label'>Suspicious</div></div>", unsafe_allow_html=True)
with c4:
    st.markdown(f"<div class='metric-card green'><div class='metric-value'>{summary.watch_count}</div><div class='metric-label'>Watch</div></div>", unsafe_allow_html=True)

# ── Suspicious Table ───────────────────────────────────────────────────────────
st.markdown("<div class='section-title'>🚨 Suspicious Activity Log</div>", unsafe_allow_html=True)
display_cols = [c for c in [
    "srcip", "record_id", "classification", "severity",
    "risk_score", "connection_count", "unique_dstip_count",
    "unique_dsport_count", "dur", "rate",
    "ml_prediction_label", "ml_attack_probability", "reason"
] if c in df.columns]

if not suspicious_df.empty:
    show_df = suspicious_df[display_cols]
    if "risk_score" in show_df.columns:
        show_df = show_df.sort_values("risk_score", ascending=False)
    st.dataframe(show_df, width="stretch", hide_index=True)
else:
    st.success("✅ No suspicious activity found.")

# ── Charts ────────────────────────────────────────────────────────────────────
st.markdown("<div class='section-title'>📊 Visual Analysis</div>", unsafe_allow_html=True)
col_left, col_right = st.columns(2)

with col_left:
    st.markdown("**Top 10 Records by Connection Count**")
    if "connection_count" in df.columns:
        id_col = "srcip" if "srcip" in df.columns else ("record_id" if "record_id" in df.columns else df.columns[0])
        top10 = df.nlargest(10, "connection_count")[[id_col, "connection_count", "classification"]]
        fig, ax = plt.subplots(figsize=(6, 4))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        colors = ["#3fb950" if str(c).strip().lower() == "normal" else "#f85149" for c in top10["classification"]]
        ax.barh(top10[id_col].astype(str), top10["connection_count"], color=colors, height=0.6)
        ax.set_xlabel("Connections", color="#8b949e", fontsize=9)
        ax.tick_params(colors="#8b949e", labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor("#21262d")
        ax.legend(handles=[
            mpatches.Patch(color="#f85149", label="Suspicious"),
            mpatches.Patch(color="#3fb950", label="Normal")
        ], facecolor="#161b22", labelcolor="#c9d1d9", fontsize=8)
        plt.tight_layout()
        st.pyplot(fig)
        plt.close()

with col_right:
    st.markdown("**Classification Breakdown**")
    if "classification" in df.columns:
        counts = df["classification"].value_counts()
        color_map = {
            "backdoor/analysis": "#f85149",
            "high risk": "#ff7b72",
            "suspicious": "#d29922",
            "watch": "#388bfd",
            "normal": "#3fb950"
        }
        pie_colors = [color_map.get(l.strip().lower(), "#8b949e") for l in counts.index]
        fig2, ax2 = plt.subplots(figsize=(6, 4))
        fig2.patch.set_facecolor("#161b22")
        ax2.set_facecolor("#0d1117")
        ax2.pie(counts, labels=counts.index, autopct="%1.1f%%", colors=pie_colors,
                startangle=90, textprops={"color": "#c9d1d9", "fontsize": 9})
        plt.tight_layout()
        st.pyplot(fig2)
        plt.close()

# Risk score chart
st.markdown("**Risk Score Distribution (Top 15)**")
if "risk_score" in df.columns:
    id_col = "srcip" if "srcip" in df.columns else ("record_id" if "record_id" in df.columns else df.columns[0])
    plot_df = df.sort_values("risk_score", ascending=False).head(15)
    fig3, ax3 = plt.subplots(figsize=(12, 3.5))
    fig3.patch.set_facecolor("#161b22")
    ax3.set_facecolor("#0d1117")
    bar_colors = ["#f85149" if s >= 80 else "#d29922" if s >= 50 else "#3fb950" for s in plot_df["risk_score"]]
    ax3.bar(plot_df[id_col].astype(str), plot_df["risk_score"], color=bar_colors, width=0.6)
    ax3.axhline(80, color="#f85149", linestyle="--", linewidth=1, alpha=0.5, label="Critical (80)")
    ax3.axhline(50, color="#d29922", linestyle="--", linewidth=1, alpha=0.5, label="High (50)")
    ax3.set_ylabel("Risk Score", color="#8b949e", fontsize=9)
    ax3.tick_params(colors="#8b949e", labelsize=8)
    ax3.tick_params(axis='x', rotation=30)
    for spine in ax3.spines.values():
        spine.set_edgecolor("#21262d")
    ax3.legend(facecolor="#161b22", labelcolor="#c9d1d9", fontsize=8)
    plt.tight_layout()
    st.pyplot(fig3)
    plt.close()

# ML Insights
if "ml_attack_probability" in df.columns:
    st.markdown("<div class='section-title'>🤖 ML Model Insights</div>", unsafe_allow_html=True)
    ml1, ml2 = st.columns(2)
    with ml1:
        avg_prob = df["ml_attack_probability"].mean()
        high_conf = len(df[df["ml_attack_probability"] > 0.8])
        st.markdown(f"""
        <div class='metric-card red' style='margin-bottom:12px;'>
            <div class='metric-value'>{avg_prob:.1%}</div>
            <div class='metric-label'>Avg Attack Probability</div>
        </div>
        <div class='metric-card yellow'>
            <div class='metric-value'>{high_conf}</div>
            <div class='metric-label'>High Confidence Detections (&gt;80%)</div>
        </div>
        """, unsafe_allow_html=True)
    with ml2:
        if "ml_prediction_label" in df.columns:
            counts_ml = df["ml_prediction_label"].value_counts()
            fig4, ax4 = plt.subplots(figsize=(5, 3))
            fig4.patch.set_facecolor("#161b22")
            ax4.set_facecolor("#0d1117")
            ml_colors = ["#f85149" if str(l).lower() != "normal" else "#3fb950" for l in counts_ml.index]
            ax4.bar(counts_ml.index, counts_ml.values, color=ml_colors, width=0.5)
            ax4.set_ylabel("Count", color="#8b949e", fontsize=9)
            ax4.tick_params(colors="#8b949e", labelsize=8)
            for spine in ax4.spines.values():
                spine.set_edgecolor("#21262d")
            plt.tight_layout()
            st.pyplot(fig4)
            plt.close()

# Download
st.markdown("<div class='section-title'>⬇️ Export</div>", unsafe_allow_html=True)
d1, d2 = st.columns(2)
with d1:
    st.download_button("🔴 Download Suspicious CSV", suspicious_df[display_cols].to_csv(index=False), "suspicious_report.csv", "text/csv")
with d2:
    st.download_button("📄 Download Full Report", df.to_csv(index=False), "full_report.csv", "text/csv")

st.markdown("""
<hr style='border-color:#21262d; margin-top:32px;'>
<div style='text-align:center; color:#8b949e; font-size:0.75rem; font-family:monospace;'>
    NETWORK BOUNCER — Dell Hackathon 2026
</div>
""", unsafe_allow_html=True)
