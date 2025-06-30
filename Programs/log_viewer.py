import streamlit as st
import re
import pandas as pd
import plotly.express as px
from time import sleep
from datetime import datetime
import json

# Event categorization module
def categorize_event(log):
    """
    Categorizes each log event into process, user, or file.
    """
    if 'EXEC' in log or 'RUN' in log:
        return 'process'
    elif 'OPN' in log or 'LOG' in log:
        return 'user'
    elif 'MOD' in log or 'DEL' in log or 'FILE' in log:
        return 'file'
    elif 'CONN' in log:
        return 'connection'
    elif 'SHDW' in log:
        return 'shadow'
    return 'unknown'

# Parse and categorize log entries
def parse_log(log):
    """
    Parse each log entry to extract timestamp, event type, user, and file/process details.
    """
    timestamp_match = re.search(r'ts:(\d+)', log)
    event_type_match = re.search(r'EVNT:(\S+)', log)
    user_match = re.search(r'usr:(\S+)', log)
    file_match = re.search(r'=>(.+)', log)

    timestamp = int(timestamp_match.group(1)) if timestamp_match else None
    event_type = event_type_match.group(1) if event_type_match else 'unknown'
    user = user_match.group(1) if user_match else 'unknown'
    file_or_process = file_match.group(1) if file_match else 'unknown'

    category = categorize_event(log)

    return {
        'timestamp': timestamp,
        'event_type': event_type,
        'user': user,
        'file_or_process': file_or_process,
        'category': category
    }

# Generate and sort the timeline
def generate_timeline(log_data):
    """
    Generates a timeline sorted by timestamp.
    """
    parsed_logs = [parse_log(log) for log in log_data]
    sorted_logs = sorted(parsed_logs, key=lambda x: x['timestamp'])
    return sorted_logs

# Convert to DataFrame for visualization
def logs_to_dataframe(timeline):
    """
    Converts the sorted timeline to a pandas DataFrame for better visualization.
    """
    return pd.DataFrame(timeline)

# Handle file reading and error checking
def process_uploaded_file(uploaded_file):
    try:
        file_content = uploaded_file.getvalue().decode("utf-8").splitlines()
        if not file_content:
            raise ValueError("The file is empty or not valid.")
        return file_content, None
    except Exception as e:
        return None, str(e)

# Function to export the logs in CSV format
def export_csv(df):
    return df.to_csv(index=False)

# Function to export the logs in JSON format
def export_json(df):
    return df.to_json(orient="records", lines=True)

# Function to export the logs in TXT format
def export_txt(df):
    return "\n".join([f"{row['timestamp']} | {row['event_type']} | {row['user']} | {row['file_or_process']} | {row['category']}" for index, row in df.iterrows()])

# Streamlit UI
def main():
    st.set_page_config(page_title="Log Categorization & Timeline", layout="wide")  # Set to 'wide' layout

    # Set custom CSS to keep sidebar static and remove the close button
    st.markdown(
        """
        <style>
            /* Hide the close button of the sidebar */
            .css-1d391kg { display: none; }  
            .css-18e3b3k { position: relative !important; }  /* Keep sidebar static */
            
            /* Sidebar Styling */
            .css-1v3fvcr { background-color: #F4F7F9; padding-top: 20px; }
            .css-18e3b3k { width: 280px; }  /* Fixed sidebar width */
            .stSidebar { font-family: 'Arial', sans-serif; }

            /* Clean table style */
            .stTable th { background-color: #00796b; color: white; }
            .stTable td { background-color: #f1f8e9; }
        </style>
        """, unsafe_allow_html=True
    )

    # Title of the app
    st.title("Log Categorization & Timeline Generation")

    # File uploader for multiple vlog files
    uploaded_files = st.sidebar.file_uploader("Choose `.vlog` log files", type="vlog", accept_multiple_files=True)

    if uploaded_files:
        # Sidebar File Metadata (Fixed Sidebar Content)
        for uploaded_file in uploaded_files:
            st.sidebar.markdown(f"### {uploaded_file.name}")
            st.sidebar.markdown(f"**File Size**: {uploaded_file.size / 1024:.2f} KB")
            
            # Show upload time instead of last modified time
            upload_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            st.sidebar.markdown(f"**Upload Time**: {upload_time}")
            st.sidebar.markdown("---")

        all_timeline_data = []
        error_messages = []

        # Iterate over each uploaded file
        for uploaded_file in uploaded_files:
            st.sidebar.text(f"Processing: {uploaded_file.name}...")
            progress_bar = st.sidebar.progress(0)

            # Process each file with error handling
            file_content, error = process_uploaded_file(uploaded_file)

            # Simulate file processing delay
            for i in range(100):
                sleep(0.02)
                progress_bar.progress(i + 1)

            if error:
                error_messages.append(f"Error with file `{uploaded_file.name}`: {error}")
                continue
            
            # If the file is valid, process it
            try:
                timeline = generate_timeline(file_content)
                if timeline:
                    all_timeline_data.extend(timeline)
                else:
                    error_messages.append(f"No valid logs found in `{uploaded_file.name}`.")
            except Exception as e:
                error_messages.append(f"Error processing file `{uploaded_file.name}`: {str(e)}")

        # If errors occurred, display them
        if error_messages:
            st.error("\n".join(error_messages))

        # If we have valid logs, display the timeline and charts
        if all_timeline_data:
            # Convert to DataFrame for visualization
            df_timeline = logs_to_dataframe(all_timeline_data)

            # Categorized Logs Section
            st.markdown(f"### Categorized Logs")
            st.write(df_timeline)

            # Event Category Distribution (Interactive Bar Chart)
            st.markdown(f"### Event Category Distribution")
            category_counts = df_timeline['category'].value_counts().reset_index()
            category_counts.columns = ['Category', 'Count']
            
            # Plot interactive bar chart using Plotly
            category_fig = px.bar(category_counts, x='Category', y='Count', color='Category', title="Event Category Distribution")
            st.plotly_chart(category_fig, use_container_width=True)

            # Event Type Distribution (Pie Chart)
            st.markdown(f"### Event Type Distribution")
            event_type_counts = df_timeline['event_type'].value_counts().reset_index()
            event_type_counts.columns = ['Event Type', 'Count']
            
            # Plot interactive pie chart using Plotly
            event_type_fig = px.pie(event_type_counts, names='Event Type', values='Count', title="Event Type Distribution")
            st.plotly_chart(event_type_fig, use_container_width=True)

            # Quick Insights
            st.markdown(f"### Quick Insights")
            st.markdown(f"**Total Events**: {len(df_timeline)}")
            st.markdown(f"**Unique Users**: {df_timeline['user'].nunique()}")
            st.markdown(f"**Unique Categories**: {df_timeline['category'].nunique()}")

            # Export Section - Single Button for Export
            st.markdown(f"### Export Data")

            export_type = st.selectbox("Select Export Format", ["CSV", "JSON", "TXT"])

            export_data = None
            if export_type == "CSV":
                export_data = export_csv(df_timeline)
            elif export_type == "JSON":
                export_data = export_json(df_timeline)
            elif export_type == "TXT":
                export_data = export_txt(df_timeline)

            # Single Download Button with Export Data
            if export_data:
                st.download_button(f"Download {export_type} File", export_data, file_name=f"logs_timeline.{export_type.lower()}", mime=f"application/{export_type.lower()}")

if __name__ == "__main__":
    main()
