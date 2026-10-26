
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# -----------------------------
# Page configuration
# -----------------------------
st.set_page_config(
    page_title="Sentinova ThreatLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Professional SOC theme
# -----------------------------
st.markdown("""
<style>
    .stApp {
        background: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stHeader"] {
        background: rgba(11, 17, 32, 0.95);
    }

    [data-testid="stSidebar"] {
        background: #111827;
        border-right: 1px solid #263449;
    }

    [data-testid="stSidebar"] * {
        color: #e5e7eb;
    }

    h1, h2, h3 {
        color: #f8fafc !important;
        letter-spacing: -0.4px;
    }

    p, label, .stCaption {
        color: #cbd5e1;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #172338, #111827);
        border: 1px solid #293950;
        padding: 18px 20px;
        border-radius: 12px;
        min-height: 115px;
    }

    [data-testid="stMetricLabel"] {
        color: #9ca3af;
    }

    [data-testid="stMetricValue"] {
        color: #f8fafc;
        font-weight: 700;
    }

    div[data-testid="stPlotlyChart"] {
        background: #111827;
        border: 1px solid #263449;
        border-radius: 12px;
        padding: 10px;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #263449;
        border-radius: 10px;
    }

    div.stButton > button,
    div.stDownloadButton > button {
        border-radius: 8px;
        font-weight: 600;
        min-height: 40px;
    }

    div.stButton > button[kind="primary"] {
        background: #2563eb;
        border-color: #2563eb;
        color: white;
    }

    div.stButton > button:hover,
    div.stDownloadButton > button:hover {
        border-color: #60a5fa;
        color: #93c5fd;
    }

    [data-testid="stAlert"] {
        border-radius: 10px;
    }

    hr {
        border-color: #263449;
    }

    footer {
        visibility: hidden;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------
# Simulated indicator data
# -----------------------------
SAMPLE_DATA = [
    {
        "id": "TL-1001", "indicator": "198.51.100.23",
        "type": "IP Address", "source": "Simulated Feed A",
        "category": "Brute Force", "confidence": 96,
        "severity": "Critical", "score": 95,
        "country": "United States", "status": "Open",
    },
    {
        "id": "TL-1002", "indicator": "203.0.113.42",
        "type": "IP Address", "source": "Simulated Feed B",
        "category": "Scanning", "confidence": 82,
        "severity": "High", "score": 78,
        "country": "Germany", "status": "Investigating",
    },
    {
        "id": "TL-1003", "indicator": "example-malware.test",
        "type": "Domain", "source": "Simulated Feed A",
        "category": "Malware", "confidence": 91,
        "severity": "Critical", "score": 92,
        "country": "Unknown", "status": "Open",
    },
    {
        "id": "TL-1004",
        "indicator": "https://phishing.example.test/login",
        "type": "URL", "source": "Simulated Feed C",
        "category": "Phishing", "confidence": 88,
        "severity": "High", "score": 81,
        "country": "Unknown", "status": "Investigating",
    },
    {
        "id": "TL-1005",
        "indicator": "44d88612fea8a8f36de82e1278abb02f",
        "type": "File Hash", "source": "Simulated Feed B",
        "category": "Malware Hash", "confidence": 99,
        "severity": "Critical", "score": 98,
        "country": "Unknown", "status": "Open",
    },
    {
        "id": "TL-1006", "indicator": "192.0.2.88",
        "type": "IP Address", "source": "Simulated Feed C",
        "category": "Suspicious Login", "confidence": 64,
        "severity": "Medium", "score": 55,
        "country": "India", "status": "Open",
    },
    {
        "id": "TL-1007", "indicator": "updates.example.test",
        "type": "Domain", "source": "Simulated Feed A",
        "category": "Suspicious Domain", "confidence": 48,
        "severity": "Low", "score": 28,
        "country": "Unknown", "status": "Closed",
    },
    {
        "id": "TL-1008", "indicator": "198.51.100.76",
        "type": "IP Address", "source": "Simulated Feed B",
        "category": "Port Scanning", "confidence": 74,
        "severity": "High", "score": 72,
        "country": "France", "status": "Open",
    },
    {
        "id": "TL-1009",
        "indicator": "suspicious-download.example.test",
        "type": "Domain", "source": "Simulated Feed C",
        "category": "Malware Delivery", "confidence": 86,
        "severity": "High", "score": 84,
        "country": "Unknown", "status": "Investigating",
    },
    {
        "id": "TL-1010", "indicator": "203.0.113.105",
        "type": "IP Address", "source": "Simulated Feed A",
        "category": "Reconnaissance", "confidence": 35,
        "severity": "Low", "score": 24,
        "country": "Japan", "status": "Closed",
    },
    {
        "id": "TL-1011", "indicator": "192.0.2.147",
        "type": "IP Address", "source": "Simulated Feed B",
        "category": "Credential Abuse", "confidence": 77,
        "severity": "Medium", "score": 62,
        "country": "India", "status": "Open",
    },
    {
        "id": "TL-1012", "indicator": "sample-ransomware.test",
        "type": "Domain", "source": "Simulated Feed C",
        "category": "Ransomware", "confidence": 94,
        "severity": "Critical", "score": 93,
        "country": "Unknown", "status": "Investigating",
    },
]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
STATUS_OPTIONS = ["Open", "Investigating", "Closed"]

SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#f59e0b",
    "Low": "#22c55e",
}

# -----------------------------
# Session state
# -----------------------------
if "threats" not in st.session_state:
    st.session_state.threats = pd.DataFrame(SAMPLE_DATA)

if "activity" not in st.session_state:
    st.session_state.activity = [
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": "ThreatLens demo initialized",
        }
    ]

df = st.session_state.threats

# -----------------------------
# Dashboard header
# -----------------------------
st.title("🛡️ Sentinova ThreatLens")
st.caption("CYBER THREAT INTELLIGENCE  |  SOC MONITORING CONSOLE")

st.warning(
    "DEMO MODE — All indicators and feed names are simulated. "
    "No live threat feeds are connected. Do not block or investigate "
    "real systems based on this sample data."
)

# -----------------------------
# Sidebar filters
# -----------------------------
st.sidebar.title("🛡️ ThreatLens")
st.sidebar.caption("THREAT INTELLIGENCE WORKBENCH")
st.sidebar.markdown("---")

search = st.sidebar.text_input(
    "🔎 Search indicators",
    placeholder="Search IP, domain, hash, category...",
)

types = st.sidebar.multiselect(
    "Indicator type",
    options=sorted(df["type"].unique()),
    default=sorted(df["type"].unique()),
)

severities = st.sidebar.multiselect(
    "Severity",
    options=SEVERITY_ORDER,
    default=SEVERITY_ORDER,
)

statuses = st.sidebar.multiselect(
    "Incident status",
    options=STATUS_OPTIONS,
    default=STATUS_OPTIONS,
)

st.sidebar.markdown("---")
st.sidebar.caption("LOCAL MVP  •  SIMULATED DATA")
st.sidebar.caption("Sentinova ThreatLens")

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
        .apply(
            lambda col: col.str.contains(
                search.strip(),
                case=False,
                regex=False,
            )
        )
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

st.markdown("### Operational Overview")
c1, c2, c3, c4 = st.columns(4)

c1.metric("TOTAL INDICATORS", total)
c2.metric("CRITICAL RISKS", critical)
c3.metric("OPEN ALERTS", open_count)
c4.metric("UNDER INVESTIGATION", investigating)

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
            color_discrete_map=SEVERITY_COLORS,
            text="Count",
        )

        fig.update_traces(
            textposition="outside",
            cliponaxis=False,
            marker_line_width=0,
        )

        fig.update_layout(
            title="Indicators by risk level",
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e5e7eb"),
            showlegend=False,
            margin=dict(l=15, r=15, t=55, b=15),
            xaxis=dict(
                title=None,
                showgrid=False,
                linecolor="#334155",
            ),
            yaxis=dict(
                title="Number of indicators",
                gridcolor="#263449",
                rangemode="tozero",
                dtick=1,
            ),
        )

        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Indicator Types")

    if filtered.empty:
        st.info("No indicator data to display.")
    else:
        type_counts = (
            filtered["type"]
            .value_counts()
            .rename_axis("Type")
            .reset_index(name="Count")
        )

        fig = px.pie(
            type_counts,
            names="Type",
            values="Count",
            hole=0.55,
            color_discrete_sequence=[
                "#60a5fa",
                "#a78bfa",
                "#2dd4bf",
                "#f59e0b",
                "#f87171",
            ],
        )

        fig.update_traces(
            textposition="inside",
            textinfo="percent",
            insidetextfont=dict(color="#ffffff", size=12),
            marker=dict(line=dict(color="#111827", width=3)),
            hovertemplate="%{label}<br>Count: %{value}<br>%{percent}<extra></extra>",
        )

        fig.update_layout(
            title="Threat intelligence distribution",
            template="plotly_dark",
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e5e7eb"),
            legend=dict(
                orientation="h",
                yanchor="top",
                y=-0.08,
                xanchor="center",
                x=0.5,
            ),
            margin=dict(l=15, r=15, t=55, b=35),
        )

        st.plotly_chart(fig, use_container_width=True)

# -----------------------------
# Indicator table and CSV export
# -----------------------------
st.markdown("---")
st.subheader("🔍 Threat Intelligence Indicators")
st.caption("Synthetic indicators for demonstration only.")

display_columns = [
    "id", "indicator", "type", "category", "source",
    "confidence", "score", "severity", "country", "status",
]

st.dataframe(
    filtered[display_columns],
    hide_index=True,
    use_container_width=True,
    column_config={
        "id": st.column_config.TextColumn("Indicator ID"),
        "indicator": st.column_config.TextColumn("Indicator"),
        "confidence": st.column_config.ProgressColumn(
            "Confidence",
            min_value=0,
            max_value=100,
            format="%d%%",
        ),
        "score": st.column_config.ProgressColumn(
            "Risk Score",
            min_value=0,
            max_value=100,
            format="%d",
        ),
        "severity": st.column_config.TextColumn("Severity"),
        "status": st.column_config.TextColumn("Status"),
    },
)

csv = filtered[display_columns].to_csv(index=False).encode("utf-8")

st.download_button(
    "⬇️ Export filtered indicators (CSV)",
    data=csv,
    file_name="threatlens_indicators.csv",
    mime="text/csv",
)

# -----------------------------
# Incident triage
# -----------------------------
st.markdown("---")
st.subheader("🚨 Incident Triage")
st.caption(
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
        list(options.keys()),
    )

    selected_id = options[selected_label]
    current_row = df[df["id"] == selected_id].iloc[0]

    new_status = st.selectbox(
        "Update status",
        STATUS_OPTIONS,
        index=STATUS_OPTIONS.index(current_row["status"]),
    )

    if st.button("Save incident status", type="primary"):
        old_status = current_row["status"]

        if old_status != new_status:
            st.session_state.threats.loc[
                st.session_state.threats["id"] == selected_id,
                "status",
            ] = new_status

            st.session_state.activity.insert(
                0,
                {
                    "time": datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "event": (
                        f"{selected_id}: {old_status} → {new_status}"
                    ),
                },
            )

            st.success(
                f"{selected_id} status updated to {new_status}."
            )
        else:
            st.info("The indicator already has that status.")

        st.rerun()

# -----------------------------
# Recent activity
# -----------------------------
st.markdown("---")
st.subheader("📋 Recent Activity")

activity_df = pd.DataFrame(st.session_state.activity)

if activity_df.empty:
    st.info("No activity recorded yet.")
else:
    st.dataframe(
        activity_df,
        hide_index=True,
        use_container_width=True,
    )

st.caption(
    "ThreatLens MVP · Local prototype · "
    "Sample data only · Not a production security system"
)
