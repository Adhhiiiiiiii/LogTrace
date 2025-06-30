import streamlit as st
import re
import pandas as pd
import io
import json
import plotly.express as px
from collections import defaultdict


# Function to parse and detect suspicious activity in logs
def detect_suspicious_activity(log_data):
    suspicious_activities = []
    ip_connections = defaultdict(list)
    process_kills = defaultdict(list)
    
    # Split log data into individual lines
    log_lines = log_data.strip().split('\n')
    
    for line in log_lines:
        timestamp_match = re.search(r'\[ts:(\d+)\]', line)
        event_match = re.search(r'EVNT:(\w+)-(\w+)', line)
        user_match = re.search(r'usr:(\w+)', line)
        file_match = re.search(r'=>(/[\w\./-]+)', line)
        ip_match = re.search(r'IP:(\d+\.\d+\.\d+\.\d+)', line)
        process_match = re.search(r'pid(\d+)', line)

        if timestamp_match and event_match:
            timestamp = int(timestamp_match.group(1))  # Convert to integer for easier filtering
            event_type = event_match.group(1)
            event_action = event_match.group(2)
            user = user_match.group(1) if user_match else None
            file = file_match.group(1) if file_match else None
            ip = ip_match.group(1) if ip_match else None
            pid = process_match.group(1) if process_match else None

            # Rule 1: Check for suspicious file modification or deletion
            suspicious_keywords = [
                "/etc/passwd", "/usr/lib/xrun.conf", "/opt/secure.shd", "KILL_proc", "XR-SHDW", "XR-DEL"
            ]
            if file and any(keyword in file for keyword in suspicious_keywords):
                severity = "High" if "/etc/passwd" in file or "XR-DEL" in event_action else "Medium"
                suspicious_activities.append((timestamp, event_type, event_action, user, file, ip, pid, severity))

            # Rule 2: Check for multiple connections from different IPs by the same user
            if ip:
                ip_connections[user].append(ip)

            # Rule 3: Check for killing processes (possible malicious action)
            if pid and event_action == 'KILL':
                process_kills[user].append(pid)

    # Flag IP connections where the same user connects from multiple IPs
    for user, ips in ip_connections.items():
        if len(set(ips)) > 2:  # More than 2 unique IPs for the same user is suspicious
            for ip in set(ips):
                suspicious_activities.append(("Multiple IP connections", user, ip))

    # Flag process kills as suspicious
    for user, pids in process_kills.items():
        if len(set(pids)) > 2:  # Killing multiple processes is unusual
            for pid in set(pids):
                suspicious_activities.append(("Multiple process kills", user, pid))

    return suspicious_activities

# Function to create a CSV output from flagged activities
def generate_csv_report(suspicious_activities):
    # Define CSV column headers
    header = ["Timestamp", "Event Type", "Action", "User", "File/Process", "IP", "PID", "Severity"]
    # Convert suspicious activities to a pandas DataFrame
    df = pd.DataFrame(suspicious_activities, columns=header)
    
    # Write to CSV in-memory (using io.StringIO)
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)  # Move to the beginning of the StringIO object
    
    return output.getvalue()

# Function to create a JSON output from flagged activities
def generate_json_report(suspicious_activities):
    # Convert suspicious activities to a list of dictionaries
    header = ["Timestamp", "Event Type", "Action", "User", "File/Process", "IP", "PID", "Severity"]
    json_data = []
    for activity in suspicious_activities:
        activity_dict = dict(zip(header, activity))
        json_data.append(activity_dict)
    
    # Convert the list to JSON
    return json.dumps(json_data, indent=4)

# Streamlit user interface
st.title('Suspicious Activity Log Analyzer')
st.write('Upload multiple .vlog files to analyze logs and detect suspicious activities.')

# File uploader widget for multiple files
uploaded_files = st.file_uploader("Choose log files", type=["txt", "log", "vlog"], accept_multiple_files=True)

# Export format selection with Radio Button
export_format = st.radio(
    "Select export format",
    ("CSV", "JSON"),
    index=0  # Default selection is CSV
)

# Variable to store suspicious activities
all_suspicious_activities = []

if uploaded_files:
    # Process each uploaded file
    for uploaded_file in uploaded_files:
        file_content = uploaded_file.getvalue().decode("utf-8")

        # Detect suspicious activities
        suspicious_activities = detect_suspicious_activity(file_content)
        all_suspicious_activities.extend(suspicious_activities)
    
    if all_suspicious_activities:
        # Display detected suspicious activities in a styled larger table
        st.write("### Detected Suspicious Activities:")
        st.dataframe(pd.DataFrame(all_suspicious_activities, columns=["Timestamp", "Event Type", "Action", "User", "File/Process", "IP", "PID", "Severity"]), width=1000, height=400)
        
        # Provide export button after file upload and activity detection
        st.write("### Export Report:")
        if export_format == "CSV":
            report = generate_csv_report(all_suspicious_activities)
            file_name = "suspicious_activity_report.csv"
            mime_type = "text/csv"
        else:
            report = generate_json_report(all_suspicious_activities)
            file_name = "suspicious_activity_report.json"
            mime_type = "application/json"
        
        st.download_button(
            label=f"Download Suspicious Activity Report ({export_format})",
            data=report,
            file_name=file_name,
            mime=mime_type
        )

        # Display Dynamic Visualizations
        st.write("### Visualizations of Suspicious Activities:")
        
        # Convert to DataFrame for visualization
        df = pd.DataFrame(all_suspicious_activities, columns=["Timestamp", "Event Type", "Action", "User", "File/Process", "IP", "PID", "Severity"])

        # Activity count by user (interactive bar chart)
        user_activity = df['User'].value_counts().reset_index()
        user_activity.columns = ['User', 'Count']
        fig_user = px.bar(user_activity, x='User', y='Count', title="Suspicious Activities by User")
        st.plotly_chart(fig_user)

        # Activity count by file/process (interactive bar chart)
        file_activity = df['File/Process'].value_counts().reset_index()
        file_activity.columns = ['File/Process', 'Count']
        fig_file = px.bar(file_activity, x='File/Process', y='Count', title="Suspicious Activities by File/Process")
        st.plotly_chart(fig_file)

    else:
        st.write("No suspicious activities detected in the uploaded log files.")
