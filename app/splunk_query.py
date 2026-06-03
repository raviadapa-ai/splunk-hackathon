import os
import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings()

SPLUNK_URL = os.getenv("SPLUNK_URL")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

query = 'search sourcetype="aiops_logs" ERROR | head 10'

response = requests.post(
    SPLUNK_URL,
    auth=HTTPBasicAuth(SPLUNK_USERNAME, SPLUNK_PASSWORD),
    data={
        "search": query,
        "output_mode": "json"
    },
    verify=False
)

print(response.status_code)
print(response.text)