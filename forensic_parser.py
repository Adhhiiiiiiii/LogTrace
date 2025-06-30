import streamlit as st
import pandas as pd
import re, io, json
from datetime import datetime
import matplotlib.pyplot as plt
import plotly.express as px
from sklearn.ensemble import IsolationForest
from scipy import stats
import requests

# ----------- Helper Functions ----------- 

def parse_line(line, log_type):
    """ Parse each log line and extract relevant data. """
    ts = re.search(r"\[ts:(\d+)]", line)
    ev = re.search(r"EVNT:(XR-\w+)", line)
    usr = re.search(r"usr:(\w+)", line)
    ip = re.search(r"IP:([\d\.]+)", line)
    fn = re.search(r"=>/(.+)", line)
    pid = re.search(r"pid(\d+)", line)
    
    return {
        "timestamp": int(ts.group(1)) if ts else None,
        "event_type": ev.group(1) if ev else None,
        "user": usr.group(1) if usr else None,
        "ip": ip.group(1) if ip else None,
        "file": "/" + fn.group(1) if fn else None,
        "pid": int(pid.group(1)) if pid else None,
        "log_type": log_type  # Add log type to the record
    }

@st.cache_data
def ip_to_geo(ip):
    """ Convert IP address to geographical coordinates. """
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json()
        loc = res.get("loc", "").split(",")
        return float(loc[0]), float(loc[1]), res.get("city"), res.get("country")
    except:
        return None, None, None, None

# ----------- Streamlit UI Design ----------- 
st.set_page_config(page_title="Log Visualizer", layout="wide")

# Header section with custom styling
st.markdown("""
    <style>
    .title {
        font-size: 36px;
        font-weight: bold;
        color: #1E3D58;
    }
    .header {
        font-size: 24px;
        color: #4B6A7E;
    }
    .subheader {
        font-size: 20px;
        color: #8D99A6;
    }
    .card {
        background-color: #f4f4f4;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
    }
    .sidebar {
        background-color: #4E6A6A;
        color: #ffffff;
    }
    /* Full-screen table styling */
    .full-table {
        width: 100% !important;
        table-layout: auto !important;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔍 **Enhanced Log Visualizer & Analyzer**")

# File uploader (for log files)
uploads = st.file_uploader("Upload .txt/.vlog files", ["txt", "vlog"], accept_multiple_files=True)
if not uploads:
    st.info("Please upload at least one log file to begin.")
    st.stop()

# Reading files and parsing logs
data = []
for f in uploads:
    log_type = f.name.split('.')[-1].upper()
    lines = f.read().decode().splitlines()
    for L in lines:
        p = parse_line(L, log_type)
        if p["timestamp"]:
            data.append(p)

df = pd.DataFrame(data)
df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
st.success(f"Successfully parsed {len(df)} log entries.")

# ----------- Tabs for Better Navigation ----------- 
tab1, tab2, tab3, tab4 = st.tabs(["📋 Summary Report", "📅 Event Timeline", "⚠️ Alerts & Anomalies", "🌍 Geo-location"])

with tab1:
    # Summary Report Section
    st.markdown("<div class='header'>Log Summary</div>", unsafe_allow_html=True)
    total_events = len(df)
    unique_users = df["user"].nunique()
    unique_event_types = df["event_type"].nunique()
    unique_ips = df["ip"].nunique()

    st.markdown(f"**Total Events:** {total_events}")
    st.markdown(f"**Unique Users:** {unique_users}")
    st.markdown(f"**Unique Event Types:** {unique_event_types}")
    st.markdown(f"**Unique IPs:** {unique_ips}")

with tab2:
    # Event Timeline Section
    st.markdown("<div class='header'>Event Timeline</div>", unsafe_allow_html=True)
    ts_grp = df.groupby(pd.Grouper(key="timestamp", freq="10S")).size().reset_index(name="count")

    # Event frequency line plot
    fig = px.line(ts_grp, x="timestamp", y="count", title="Event Count (10-second bins)", 
                  labels={"timestamp": "Time", "count": "Event Count"})
    st.plotly_chart(fig)

    # Detailed insights on the timeline
    st.markdown("""
    ### Event Insights:
    - This graph shows the number of events over 10-second intervals.
    - Spikes in the chart could represent unusual activities such as login attempts or bulk data access.
    - **Highlighting Trends**: If you notice spikes, it could indicate a specific **event type** dominating at that time.
    - **Recommendation**: Drill down to investigate further for high frequency access or failed login attempts.
    """)

    # Allow download of the timeline as PNG
    buf = io.BytesIO()
    plt.figure(figsize=(8, 3))
    plt.plot(ts_grp["timestamp"], ts_grp["count"], "-o")
    plt.title("Event Frequency Over Time")
    plt.xlabel("Time")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(buf, format="png")
    st.download_button("Download Timeline PNG", buf.getvalue(), file_name="event_timeline.png")

with tab3:
    # Anomaly Detection (Alerts)
    st.markdown("<div class='header'>Suspicious Activity Alerts</div>", unsafe_allow_html=True)

    # Z-score Anomaly Detection
    ts_grp["zscore"] = stats.zscore(ts_grp["count"])
    zs = ts_grp[ts_grp["zscore"].abs() > 2]
    st.write("🔺 **Z-score Anomalies**:")
    st.dataframe(zs, use_container_width=True)

    st.markdown("""
    ### Z-score Anomalies:
    - Z-scores above 2 (or below -2) indicate values that are significantly different from the mean.
    - Events with **high frequency** or **low frequency** at certain times could be potential anomalies.
    - **Example**: A large spike in event count might indicate a failed login attack or bulk data extraction.

    **Recommendation**: Investigate the specific time window for possible system issues, misconfigurations, or security events.
    """)

    # Isolation Forest Anomaly Detection
    X = ts_grp["count"].values.reshape(-1, 1)
    iso = IsolationForest(contamination=0.05, random_state=42).fit(X)
    ts_grp["anomaly"] = iso.predict(X)
    iso_ano = ts_grp[ts_grp["anomaly"] == -1]
    st.write("🔻 **Isolation Forest Anomalies**:")
    st.dataframe(iso_ano, use_container_width=True)

    st.markdown("""
    ### Isolation Forest Anomalies:
    - The Isolation Forest model identifies outliers by isolating them in a decision tree structure.
    - Anomalies detected here might indicate unusual **system behavior** or malicious activity.
    - **Example**: Multiple failed login attempts from the same IP, access to sensitive files.

    **Recommendation**: Review these anomalies to determine if they align with any suspicious patterns.
    """)

    # Plot anomalies on timeline chart
    fig2 = px.scatter(ts_grp, x="timestamp", y="count", color=ts_grp["anomaly"].map({1: "Normal", -1: "Anomaly"}),
                      title="Anomalous Events in Time", labels={"timestamp": "Time", "count": "Event Count"})
    st.plotly_chart(fig2)

with tab4:
    # Geo-location of IPs Section
    st.markdown("<div class='header'>Geo-location of IP Addresses</div>", unsafe_allow_html=True)
    geo = df["ip"].dropna().unique()
    geo_df = pd.DataFrame([{
        "ip": ip, 
        **dict(zip(("lat", "lon", "city", "country"), ip_to_geo(ip)))
    } for ip in geo])

    merged = df.merge(geo_df, on="ip", how="left")
    merged_filtered = merged.dropna(subset=["lat", "lon"])

    if not merged_filtered.empty:
        fig_geo = px.scatter_mapbox(merged_filtered, lat="lat", lon="lon", color="event_type",
                                    hover_data=["user", "ip", "city", "country"], zoom=2, height=400)
        fig_geo.update_layout(mapbox_style="open-street-map")
        st.plotly_chart(fig_geo)
    else:
        st.info("No valid geo-location data available for this log file.")

# ----------- Data Export Section ----------- 
st.subheader("📁 Export Parsed Data")

# Format selection
opt = st.radio("Select export format", ["JSON", "CSV", "TXT"], horizontal=True)

# Prepare data for export
df_export = df.copy()
df_export["timestamp"] = df_export["timestamp"].astype(str)  # Convert datetime to string
df_export = df_export.where(pd.notnull(df_export), None)  # Convert NaN to None for JSON compatibility

if opt == "JSON":
    st.download_button("Download JSON", json.dumps(df_export.to_dict("records"), indent=2), file_name="logs.json")
elif opt == "CSV":
    st.download_button("Download CSV", df.to_csv(index=False), file_name="logs.csv")
else:
    st.download_button("Download TXT", df.to_string(index=False), file_name="logs.txt")
