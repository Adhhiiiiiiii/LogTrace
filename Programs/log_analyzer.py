import streamlit as st
import pandas as pd
import re, io, json
from datetime import datetime
import matplotlib.pyplot as plt
import plotly.express as px
from sklearn.ensemble import IsolationForest
from scipy import stats
import requests

# ----------- Helpers ----------- 
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
        "log_type": log_type  # Add log type to the record
    }

@st.cache_data
def ip_to_geo(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json()
        loc = res.get("loc","").split(",")
        return float(loc[0]), float(loc[1]), res.get("city"), res.get("country")
    except:
        return None, None, None, None

# ----------- App UI ----------- 
st.title("🔍 Enhanced Log Visualizer & Exporter")

# Multiple file uploads
uploads = st.file_uploader("Upload .txt/.vlog files", ["txt", "vlog"], accept_multiple_files=True)
if not uploads:
    st.info("Upload at least one log file to begin.")
    st.stop()

data = []
for f in uploads:
    # Determine log type based on the file extension
    log_type = f.name.split('.')[-1].upper()  # either 'TXT' or 'VLOG'
    
    # Read file content
    lines = f.read().decode().splitlines()
    for L in lines:
        p = parse_line(L, log_type)
        if p["timestamp"]:
            data.append(p)

df = pd.DataFrame(data)
df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
st.success(f"Parsed {len(df)} entries.")

# ----------- Geo-mapping IPs ----------- 
st.subheader("🌍 Geo-locate IP addresses")
geo = df["ip"].dropna().unique()
geo_df = pd.DataFrame([{"ip":ip, **dict(zip(("lat","lon","city","country"), ip_to_geo(ip))) } for ip in geo])
merged = df.merge(geo_df, on="ip", how="left")
fig_geo = px.scatter_mapbox(merged.dropna(subset=["lat","lon"]), lat="lat", lon="lon",
                            color="event_type", hover_data=["user","ip","city","country"],
                            zoom=1, height=400)
fig_geo.update_layout(mapbox_style="open-street-map", mapbox_zoom=2)
st.plotly_chart(fig_geo)

# ----------- Event Frequency & Export PNG plot ----------- 
st.subheader("📊 Event Frequency Over Time")
ts_grp = df.groupby(pd.Grouper(key="timestamp", freq="10S")).size().reset_index(name="count")
fig = px.line(ts_grp, x="timestamp", y="count", title="Event Count (10‑sec bins)")
st.plotly_chart(fig)

buf = io.BytesIO()
plt.figure(figsize=(8,3))
plt.plot(ts_grp["timestamp"], ts_grp["count"], "-o")
plt.title("Event Frequency Over Time")
plt.xlabel("Time"); plt.ylabel("Count"); plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(buf, format="png")
st.download_button("Download Frequency PNG", buf.getvalue(), file_name="freq.png")

# ----------- User Activity Heatmap ----------- 
st.subheader("👤 User vs Event Heatmap")
ue = df.groupby(["user","event_type"]).size().reset_index(name="count")
hm = px.density_heatmap(ue, x="user", y="event_type", z="count", color_continuous_scale="Viridis")
st.plotly_chart(hm)

# ----------- Anomaly Detection ----------- 
st.subheader("⚠️ Anomalies: Z‑score & Isolation Forest")

# Z‑score on event counts
ts_grp["zscore"] = stats.zscore(ts_grp["count"])
zs = ts_grp[ts_grp["zscore"].abs() > 2]
st.write("🔺 Z‑score anomalies:")
st.dataframe(zs)

# Isolation Forest on features timestamp ordinal + event count
X = ts_grp["count"].values.reshape(-1,1)
iso = IsolationForest(contamination=0.05, random_state=42).fit(X)
ts_grp["anomaly"] = iso.predict(X)
iso_ano = ts_grp[ts_grp["anomaly"] == -1]
st.write("🔻 Isolation Forest anomalies:")
st.dataframe(iso_ano)

# Highlight anomalies on time chart
fig2 = px.scatter(ts_grp, x="timestamp", y="count", color=ts_grp["anomaly"].map({1:"normal",-1:"anomaly"}))
st.plotly_chart(fig2)

# ----------- Data Export ----------- 
st.subheader("📁 Export Parsed Data")

# Using custom CSS to display radio buttons inline
st.markdown(
    """
    <style>
    .stRadio > div {
        display: inline-block;
        margin-right: 15px;
    }
    </style>
    """, 
    unsafe_allow_html=True
)

# Format selection using radio buttons
opt = st.radio("Select export format", ["JSON", "CSV", "TXT"], horizontal=True)

# Prepare data for export by converting all datetime columns to string
df_export = df.copy()
df_export["timestamp"] = df_export["timestamp"].astype(str)  # Convert to string

# Convert NaN values to None (JSON serializable)
df_export = df_export.where(pd.notnull(df_export), None)

# Exporting based on selected option
if opt == "JSON":
    st.download_button(
        "Download JSON", 
        json.dumps(df_export.to_dict("records"), indent=2), 
        file_name="logs.json"
    )
elif opt == "CSV":
    st.download_button(
        "Download CSV", 
        df.to_csv(index=False), 
        file_name="logs.csv"
    )
else:
    st.download_button(
        "Download TXT", 
        df.to_string(index=False), 
        file_name="logs.txt"
    )
