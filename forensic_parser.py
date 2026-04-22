```python
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
        "log_type": log_type
    }

@st.cache_data
def ip_to_geo(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json()
        loc = res.get("loc", "").split(",")
        return float(loc[0]), float(loc[1]), res.get("city"), res.get("country")
    except:
        return None, None, None, None

# ----------- Streamlit UI ----------- 

st.set_page_config(page_title="Log Visualizer", layout="wide")

st.title("🔍 Enhanced Log Visualizer & Analyzer")

# ----------- DEMO MODE + UPLOAD ----------- 

uploads = st.file_uploader("Upload .txt/.vlog files", ["txt", "vlog"], accept_multiple_files=True)
use_demo = st.checkbox("Use Demo Sample File")

files_to_process = []

if uploads:
    files_to_process = uploads

elif use_demo:
    try:
        with open("Sample Files/file.vlog", "r") as f:
            demo_content = f.read()
        files_to_process = [io.StringIO(demo_content)]
        st.info("Using demo sample file from repository.")
    except Exception as e:
        st.error(f"Failed to load demo file: {e}")
        st.stop()
else:
    st.info("Upload a file or enable demo mode.")
    st.stop()

# ----------- PARSING ----------- 

data = []

for f in files_to_process:
    if hasattr(f, "name"):
        log_type = f.name.split('.')[-1].upper()
        content = f.read().decode("utf-8", errors="ignore")
    else:
        log_type = "VLOG"
        content = f.getvalue()

    lines = content.splitlines()

    for L in lines:
        p = parse_line(L, log_type)
        if p["timestamp"]:
            data.append(p)

df = pd.DataFrame(data)

if df.empty:
    st.warning("No valid log entries found.")
    st.stop()

df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

st.success(f"Parsed {len(df)} log entries.")

# ----------- TABS ----------- 

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Summary Report",
    "📅 Event Timeline",
    "⚠️ Alerts & Anomalies",
    "🌍 Geo-location"
])

# ----------- SUMMARY ----------- 

with tab1:
    st.subheader("Log Summary")

    st.write(f"Total Events: {len(df)}")
    st.write(f"Unique Users: {df['user'].nunique()}")
    st.write(f"Unique Event Types: {df['event_type'].nunique()}")
    st.write(f"Unique IPs: {df['ip'].nunique()}")

# ----------- TIMELINE ----------- 

with tab2:
    st.subheader("Event Timeline")

    ts_grp = df.groupby(pd.Grouper(key="timestamp", freq="10S")).size().reset_index(name="count")

    fig = px.line(ts_grp, x="timestamp", y="count", title="Event Count")
    st.plotly_chart(fig)

    buf = io.BytesIO()
    plt.figure(figsize=(8, 3))
    plt.plot(ts_grp["timestamp"], ts_grp["count"], "-o")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(buf, format="png")

    st.download_button("Download Timeline PNG", buf.getvalue(), "timeline.png")

# ----------- ANOMALIES ----------- 

with tab3:
    st.subheader("Anomaly Detection")

    ts_grp["zscore"] = stats.zscore(ts_grp["count"])
    st.write("Z-score anomalies:")
    st.dataframe(ts_grp[ts_grp["zscore"].abs() > 2])

    X = ts_grp["count"].values.reshape(-1, 1)
    iso = IsolationForest(contamination=0.05, random_state=42).fit(X)
    ts_grp["anomaly"] = iso.predict(X)

    st.write("Isolation Forest anomalies:")
    st.dataframe(ts_grp[ts_grp["anomaly"] == -1])

    fig2 = px.scatter(ts_grp, x="timestamp", y="count", color=ts_grp["anomaly"].map({1:"Normal",-1:"Anomaly"}))
    st.plotly_chart(fig2)

# ----------- GEO ----------- 

with tab4:
    st.subheader("Geo-location")

    geo_ips = df["ip"].dropna().unique()

    geo_data = []
    for ip in geo_ips:
        lat, lon, city, country = ip_to_geo(ip)
        geo_data.append({
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "city": city,
            "country": country
        })

    geo_df = pd.DataFrame(geo_data)

    merged = df.merge(geo_df, on="ip", how="left")
    merged = merged.dropna(subset=["lat", "lon"])

    if not merged.empty:
        fig_geo = px.scatter_mapbox(
            merged,
            lat="lat",
            lon="lon",
            color="event_type",
            hover_data=["user", "ip", "city", "country"],
            zoom=2
        )
        fig_geo.update_layout(mapbox_style="open-street-map")
        st.plotly_chart(fig_geo)
    else:
        st.info("No geo data available.")

# ----------- EXPORT ----------- 

st.subheader("Export Data")

opt = st.radio("Format", ["JSON", "CSV", "TXT"], horizontal=True)

df_export = df.copy()
df_export["timestamp"] = df_export["timestamp"].astype(str)

if opt == "JSON":
    st.download_button("Download JSON", json.dumps(df_export.to_dict("records"), indent=2), "logs.json")

elif opt == "CSV":
    st.download_button("Download CSV", df_export.to_csv(index=False), "logs.csv")

else:
    st.download_button("Download TXT", df_export.to_string(index=False), "logs.txt")
```
