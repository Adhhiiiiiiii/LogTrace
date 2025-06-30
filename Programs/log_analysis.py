import streamlit as st
import pandas as pd
import re
import json
from datetime import datetime

# Function to detect more complex anomalous activity
def detect_anomalies(log_data):
    anomalies = []
    
    # Define more complex rules for suspicious behavior:
    suspicious_patterns = [
        (r'Create shadow copy', 'Shadow Copy Created'),
        (r'Delete process', 'Process Deleted'),
        (r'Unauthorized access', 'Unauthorized Access Attempt'),
        (r'Failed login', 'Failed Login Attempt'),
        (r'Process [\w]+ started by [^user]*$', 'Suspicious Process Started'),
        (r'Network connection established', 'Suspicious Network Activity'),
    ]
    
    # Check each log entry for suspicious behavior
    for index, line in log_data.iterrows():
        log_entry = line['log']
        
        for pattern, alert_type in suspicious_patterns:
            if re.search(pattern, log_entry):
                anomalies.append({'index': index, 'log': log_entry, 'type': alert_type, 'timestamp': line['timestamp']})
                
    return anomalies

# Function to read and validate vlog files (including timestamp extraction)
def read_log_file(file, input_format):
    try:
        if input_format == "vlog":
            # Read file into pandas dataframe, assuming each line is a single log entry
            logs = pd.read_csv(file, header=None, names=['log'])
            
            # Extract timestamp from log (e.g., ts:7664148)
            logs['timestamp'] = logs['log'].apply(lambda x: re.search(r'ts:(\d+)', x).group(1) if re.search(r'ts:(\d+)', x) else None)
            
            # Convert timestamp to seconds since epoch (if needed)
            logs['timestamp'] = pd.to_datetime(logs['timestamp'], unit='s', errors='coerce')
            
            # Handle cases where conversion failed
            if logs['timestamp'].isnull().any():
                st.error(f"Invalid timestamp format in {file.name}. Please check the file.")
                return None
            
            # Check for empty logs
            if logs.empty:
                st.warning(f"The file {file.name} is empty.")
                return None
            
            return logs
        else:
            st.error(f"Unsupported input file format: {input_format}")
            return None
    except Exception as e:
        st.error(f"Error reading the file: {e}")
        return None

# Function to download anomalies as CSV or JSON
def download_anomalies(anomalies, output_format):
    if anomalies:
        anomaly_df = pd.DataFrame(anomalies)

        # Provide an option for CSV or JSON download based on user choice
        if output_format == "CSV":
            # Convert DataFrame to CSV
            csv = anomaly_df.to_csv(index=False)
            st.download_button(label="Download Anomalies as CSV", data=csv, file_name="flagged_anomalies.csv", mime="text/csv")
        
        elif output_format == "JSON":
            # Convert DataFrame to JSON
            json_data = anomaly_df.to_json(orient="records", date_format="iso")
            st.download_button(label="Download Anomalies as JSON", data=json_data, file_name="flagged_anomalies.json", mime="application/json")

# Streamlit App UI
def main():
    st.title("Log File Anomaly Detection")

    st.write("Upload your log files for analysis.")

    # Choose input file format
    input_format = st.radio("Choose the input file format", ("vlog",))  # Only vlog for now
    uploaded_files = st.file_uploader("Choose log files", type=[input_format], accept_multiple_files=True)

    if uploaded_files:
        all_anomalies = []

        # Choose output format (CSV or JSON)
        output_format = st.radio("Choose the export format", ("CSV", "JSON"))

        for uploaded_file in uploaded_files:
            st.write(f"Analyzing file: {uploaded_file.name}")
            
            # Read and validate the log file based on the input format
            logs = read_log_file(uploaded_file, input_format)

            if logs is not None:
                # Detect anomalies in the log data
                anomalies = detect_anomalies(logs)
                
                if anomalies:
                    # Add anomalies to the list
                    for anomaly in anomalies:
                        all_anomalies.append({
                            'File': uploaded_file.name,
                            'Index': anomaly['index'],
                            'Timestamp': anomaly['timestamp'],
                            'Log Entry': anomaly['log'],
                            'Anomaly Type': anomaly['type']
                        })
                else:
                    st.write(f"No anomalies detected in {uploaded_file.name}")

        if all_anomalies:
            # Show the flagged anomalies in a table
            st.write("Flagged Anomalies:")
            anomaly_df = pd.DataFrame(all_anomalies)
            st.dataframe(anomaly_df)
            
            # Allow the user to download the anomalies
            download_anomalies(all_anomalies, output_format)
        else:
            st.write("No anomalies detected across all files.")

if __name__ == "__main__":
    main()
