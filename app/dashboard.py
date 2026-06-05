import streamlit as st
import requests
import pandas as pd

API_URL = "http://localhost:8002"

st.set_page_config(
    page_title="Splunk AIOps Copilot",
    layout="wide"
)

st.title("🚨 Splunk AIOps Copilot Dashboard")

# Dashboard Summary
dashboard = requests.get(f"{API_URL}/dashboard").json()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Incidents", dashboard["total_incidents"])
col2.metric("Open", dashboard["status_summary"]["open"])
col3.metric("Approved", dashboard["status_summary"]["approved"])
col4.metric("Executed", dashboard["status_summary"]["executed"])

st.divider()

st.subheader("Severity Summary")

severity_df = pd.DataFrame(
    dashboard["severity_summary"].items(),
    columns=["Severity", "Count"]
)

st.bar_chart(
    severity_df.set_index("Severity")
)

st.divider()

st.subheader("Recent Incidents")

incidents = dashboard["recent_incidents"]

if incidents:
    df = pd.DataFrame(incidents)
    st.dataframe(df, use_container_width=True)

    latest = incidents[-1]

    st.subheader("Latest Incident")

    st.write(f"**Incident ID:** {latest['incident_id']}")
    st.write(f"**Status:** {latest['status']}")
    st.write(f"**Severity:** {latest['severity']}")
    st.write(f"**Root Cause:** {latest['root_cause']}")

    st.text_area(
        "AI Summary",
        latest["summary"],
        height=250
    )

else:
    st.info("No incidents found.")