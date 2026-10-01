# Automated Phishing Email Header Analyser & Live Threat Intel Pipeline

## Project Overview
This repository features a production-grade, API-driven Python pipeline designed to automate the triage workflows of a Tier-1 Security Operations Center (SOC) analyst when inspecting suspected phishing emails.

The tool ingests raw text email files (`.eml`), utilizes regex-optimized filters to trace the routing header topology, extracts the foreign source IP address, and programmatically queries the **AbuseIPDB REST API** to generate live, data-driven security verdicts.

## Operational Pipeline Architecture
1. **Header Parsing Ingestion:** Leverages the native Python `email` module to map text envelopes into structured metadata dictionaries.
2. **Adversarial IP Tracing:** Utilizes regex rules to bypass internal infrastructure hops and isolate the boundary source IP address.
3. **External API Enrichment:** Executes dynamic `GET` requests to external intelligence feeds to capture reputation metric indices.
4. **JSON Incident Verdict:** Generates localized incident response output vectors, assigning automated triage actions based on historical confidence intervals.

## How to Deploy and Run
1. Clone the repository.
2. Install the necessary network dependency: `pip install -r requirements.txt`
3. Open `email_analyser.py` and replace `YOUR_API_KEY_HERE` with a valid, free AbuseIPDB API key token.
4. Execute the pipeline: `python email_analyser.py`
5. Inspect the newly compiled forensic JSON evidence file: `incident_verdict.json`
