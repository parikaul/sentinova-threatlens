import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
st.set_page_config(
    page_title="Sentinova ThreatLens",
    page_icon="🛡️",
    layout="wide"
)
# -----------------------------
# Sample data: simulated only
# -----------------------------
SAMPLE_DATA = [
    {"id": "TL-1001", "indicator": "198.51.100.23", "type": "IP Address",
     "source": "Simulated Feed A", "category": "Brute Force",
     "confidence": 96, "severity": "Critical", "score": 95,
     "country": "United States", "status": "Open"},
    {"id": "TL-1002", "indicator": "203.0.113.42", "type": "IP Address",
     "source": "Simulated Feed B", "category": "Scanning",
     "confidence": 82, "severity": "High", "score": 78,
     "country": "Germany", "status": "Investigating"},
    {"id": "TL-1003", "indicator": "example-malware.test", "type": "Domain",
     "source": "Simulated Feed A", "category": "Malware",
     "confidence": 91, "severity": "Critical", "score": 92,
     "country": "Unknown", "status": "Open"},
    {"id": "TL-1004", "indicator": "https://phishing.example.test/login",
     "type": "URL", "source": "Simulated Feed C",
     "category": "Phishing", "confidence": 88, "severity": "High",
     "score": 81, "country": "Unknown", "status": "Investigating"},
    {"id": "TL-1005", "indicator": "44d88612fea8a8f36de82e1278abb02f",
     "type": "File Hash", "source": "Simulated Feed B",
     "category": "Malware Hash", "confidence": 99, "severity": "Critical",
     "score": 98, "country": "Unknown", "status": "Open"},
    {"id": "TL-1006", "indicator": "192.0.2.88", "type": "IP Address",
     "source": "Simulated Feed C", "category": "Suspicious Login",
     "confidence": 64, "severity": "Medium", "score": 55,
     "country": "India", "status": "Open"},
    {"id": "TL-1007", "indicator": "updates.example.test", "type": "Domain",
     "source": "Simulated Feed A", "category": "Suspicious Domain",
     "confidence": 48, "severity": "Low", "score": 28,
     "country": "Unknown", "status": "Closed"},
    {"id": "TL-1008", "indicator": "198.51.100.76", "type": "IP Address",
     "source": "Simulated Feed B", "category": "Port Scanning",
     "confidence": 74, "severity": "High", "score": 72,
     "country": "France", "status": "Open"},
    {"id": "TL-1009", "indicator": "suspicious-download.example.test",
     "type": "Domain", "source": "Simulated Feed C",
     "category": "Malware Delivery", "confidence": 86,
     "severity": "High", "score": 84, "country": "Unknown",
     "status": "Investigating"},
    {"id": "TL-1010", "indicator": "203.0.113.105", "type": "IP Address",
     "source": "Simulated Feed A", "category": "Reconnaissance",
     "confidence": 35, "severity": "Low", "score": 24,
     "country": "Japan", "status": "Closed"},
    {"id": "TL-1011", "indicator": "192.0.2.147", "type": "IP Address",
     "source": "Simulated Feed B", "category": "Credential Abuse",
     "confidence": 77, "severity": "Medium", "score": 62,
     "country": "India", "status": "Open"},
    {"id": "TL-1012", "indicator": "sample-ransomware.test",
     "type": "Domain", "source": "Simulated Feed C",
     "category": "Ransomware", "confidence": 94,
     "severity": "Critical", "score": 93,
     "country": "Unknown", "status": "Investigating"},
]
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
STATUS_OPTIONS = ["Open", "Investigating", "Closed"]
if "threats" not in st.session_state:
    st.session_state.threats = pd.DataFrame(SAMPLE_DATA)
if "activity" not in st.session_state:
    st.session_state.activity = [
        {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "event": "ThreatLens demo initialized"}
    ]
df = st.session_state.threats
# -----------------------------
# Header
# -----------------------------
st.title("🛡️ Sentinova ThreatLens")
st.caption(
    "CYBER THREAT INTELLIGENCE  |  SOC MONITORING CONSOLE"
)
st.warning(
    "DEMO MODE — All indicators and feed names are simulated. "
    "No live threat feeds are connected. Do not block or investigate "
    "real systems based on this sample data."
)
# -----------------------------
# Sidebar filters
# -----------------------------
st.sidebar.title("ThreatLens")
st.sidebar.caption("Threat Intelligence Workbench")
st.sidebar.markdown("---")
search = st.sidebar.text_input(
    "🔎 Search indicators",
    placeholder="Search IP, domain, hash, category..."
)
types = st.sidebar.multiselect(
    "Indicator type",
    options=sorted(df["type"].unique()),
    default=sorted(df["type"].unique())
)
severities = st.sidebar.multiselect(
    "Severity",
    options=SEVERITY_ORDER,
    default=SEVERITY_ORDER
)
statuses = st.sidebar.multiselect(
    "Incident status",
    options=STATUS_OPTIONS,
    default=STATUS_OPTIONS
)
st.sidebar.markdown("---")
st.sidebar.caption("Sentinova ThreatLens MVP · Local demo")
# -----------------------------
# Filtering
# -----------------------------
filtered = df[
    df["type"].isin(types)
    & df["severity"].isin(severities)
    & df["status"].isin(statuses)
].copy()
if search.strip():
    searchable = (
        filtered.astype(str)
        .apply(lambda col: col.str.contains(
            search.strip(), case=False, regex=False
        ))
        .any(axis=1)
    )
    filtered = filtered[searchable]
# -----------------------------
# KPI cards
# -----------------------------
total = len(filtered)
critical = int((filtered["severity"] == "Critical").sum())
open_count = int((filtered["status"] == "Open").sum())
investigating = int(
    (filtered["status"] == "Investigating").sum()
)
c1, c2, c3, c4 = st.columns(4)
c1.metric("Indicators", total)
c2.metric("Critical Risks", critical)
c3.metric("Open Alerts", open_count)
c4.metric("Under Investigation", investigating)
st.markdown("---")
# -----------------------------
# Charts
# -----------------------------
left, right = st.columns(2)
with left:
    st.subheader("Threat Severity")
    if filtered.empty:
        st.info("No indicators match the selected filters.")
    else:
        severity_counts = (
            filtered["severity"]
            .value_counts()
            .reindex(SEVERITY_ORDER, fill_value=0)
            .rename_axis("Severity")
            .reset_index(name="Count")
        )
        fig = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            color="Severity",
            category_orders={"Severity": SEVERITY_ORDER},
            title="Indicators by risk level",
            color_discrete_map={
                "Critical": "#dc2626",
                "High": "#f97316",
                "Medium": "#eab308",
                "Low": "#22c55e",
            }
        )
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
with right:
    st.subheader("Indicator Types")
    if filtered.empty:
        st.info("No indicator data to display.")
    else:
        type_counts = (
            filtered["type"].value_counts()
            .rename_axis("Type")
            .reset_index(name="Count")
        )
        fig = px.pie(
            type_counts,
            names="Type",
            values="Count",
            hole=0.48,
            title="Threat intelligence distribution"
        )
        st.plotly_chart(fig, use_container_width=True)
# -----------------------------
# Indicator table
# -----------------------------
st.markdown("---")
st.subheader("🔍 Threat Intelligence Indicators")
st.caption("Synthetic indicators for demonstration only.")
display_columns = [
    "id", "indicator", "type", "category", "source",
    "confidence", "score", "severity", "country", "status"
]
st.dataframe(
    filtered[display_columns],
    hide_index=True,
    use_container_width=True,
    column_config={
        "confidence": st.column_config.ProgressColumn(
            "Confidence",
            min_value=0,
            max_value=100,
            format="%d%%"
        ),
        "score": st.column_config.ProgressColumn(
            "Risk Score",
            min_value=0,
            max_value=100,
            format="%d"
        )
    }
)
csv = filtered[display_columns].to_csv(index=False).encode("utf-8")
st.download_button(
    "⬇️ Export filtered indicators (CSV)",
    data=csv,
    file_name="threatlens_indicators.csv",
    mime="text/csv"
)
# -----------------------------
# Incident management
# -----------------------------
st.markdown("---")
st.subheader("🚨 Incident Triage")
st.write(
    "Select a demo indicator to update its status. "
    "Changes persist in this Streamlit session."
)
if df.empty:
    st.info("No indicators available.")
else:
    options = {
        f'{row["id"]} — {row["indicator"]}': row["id"]
        for _, row in df.iterrows()
    }
    selected_label = st.selectbox(
        "Select indicator",
        list(options.keys())
    )
    selected_id = options[selected_label]
    current_row = df[df["id"] == selected_id].iloc[0]
    new_status = st.selectbox(
        "Update status",
        STATUS_OPTIONS,
        index=STATUS_OPTIONS.index(current_row["status"])
    )
    if st.button("Save incident status", type="primary"):
        old_status = current_row["status"]
        st.session_state.threats.loc[
            st.session_state.threats["id"] == selected_id,
            "status"
        ] = new_status
        st.session_state.activity.insert(0, {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": (
                f'{selected_id}: {old_status} → {new_status}'
            )
        })
        st.success(
            f"{selected_id} status updated to {new_status}."
        )
        st.rerun()
# -----------------------------
# Activity log
# -----------------------------
st.markdown("---")
st.subheader("📋 Recent Activity")
st.dataframe(
    pd.DataFrame(st.session_state.activity),
    hide_index=True,
    use_container_width=True
)
st.caption(
    "ThreatLens MVP · Local prototype · "
    "Sample data only · Not a production security system"
)
