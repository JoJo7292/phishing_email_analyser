import os
import re
import json
from email import message_from_string
import requests

class PhishingEmailAnalyser:
    def __init__(self, raw_email_path, api_key):
        self.raw_email_path = raw_email_path
        self.api_key = api_key
        # Industry standard fallback: AbuseIPDB endpoint for threat metrics
        self.api_url = "https://abuseipdb.com"
        self.metadata = {}
        self.threat_intel = {}

    def parse_email_headers(self):
        """Extracts and normalizes core header telemetry from a raw email file (.eml)."""
        if not os.path.exists(self.raw_email_path):
            raise FileNotFoundError(f"Target email file missing at: {self.raw_email_path}")

        print(f"[*] Ingesting raw email payload from: {self.raw_email_path}")
        with open(self.raw_email_path, "r", encoding="utf-8") as f:
            raw_content = f.read()

        # Parse string into an executable email message object
        msg = message_from_string(raw_content)
        
        # Extract core text envelopes
        self.metadata['From'] = msg.get('From', 'Unknown Sender')
        self.metadata['To'] = msg.get('To', 'Unknown Recipient')
        self.metadata['Subject'] = msg.get('Subject', '(No Subject)')
        self.metadata['Date'] = msg.get('Date', 'Unknown Date')
        
        # Extract the 'Received' routing paths to isolate the source IP
        received_headers = msg.get_all('Received', [])
        self.metadata['Source_IP'] = self.extract_source_ip(received_headers)
        
        print(f"[+] Extraction complete. Isolated Source IP: {self.metadata['Source_IP']}")
        return self.metadata

    def extract_source_ip(self, received_headers):
        """Uses Regex optimization to trace the initial inbound hop IP address."""
        # Regex matching standard IPv4 structures
        ip_pattern = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        
        # Inspect the chronological earliest header (usually at the bottom of the list)
        if received_headers:
            for header in reversed(received_headers):
                matches = re.findall(ip_pattern, header)
                for ip in matches:
                    # Ignore internal private network ranges (192.168.x.x, 10.x.x.x, 127.x.x.x)
                    if not ip.startswith(('10.', '192.168.', '127.0.0.')):
                        return ip
        return "Unknown / Internal Source"

    def fetch_threat_intelligence(self):
        """Queries live AbuseIPDB threat intelligence database over REST API endpoint."""
        source_ip = self.metadata.get('Source_IP')
        if source_ip == "Unknown / Internal Source" or not source_ip:
            print("[-] Aborting API Query: Valid public source IP not found.")
            return

        print(f"[*] Querying AbuseIPDB Threat Intel database for IP: {source_ip}...")
        
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        querystring = {
            'ipAddress': source_ip,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }

        try:
            response = requests.get(self.api_url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()['data']
                self.threat_intel = {
                    "is_public": data.get("isPublic"),
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "total_reports": data.get("totalReports")
                }
                print(f"[!] Threat Intel Retreived. Abuse Confidence Score: {self.threat_intel['abuse_confidence_score']}%")
            else:
                print(f"[-] API connection error. Status code: {response.status_code}")
                self.threat_intel = {"error": f"Failed connection. HTTP {response.status_code}"}
        except Exception as e:
            print(f"[-] Critical exception during API fetch: {str(e)}")
            self.threat_intel = {"error": "Connection Timeout / Exception"}

    def compile_triage_verdict(self, output_path="incident_verdict.json"):
        """Applies data-driven risk scoring to generate an automated triage action plan."""
        confidence_score = self.threat_intel.get('abuse_confidence_score', 0)
        
        # Risk Determination Thresholds
        if confidence_score >= 50:
            verdict = "MALICIOUS (PHISHING)"
            action = "Isolate host immediately, purge sender from mail server, block source IP at perimeter firewall."
        elif 0 < confidence_score < 50:
            verdict = "SUSPICIOUS / LOW REPUTATION"
            action = "Flag email banner for user awareness, move payload to sandbox for deep detonation."
        else:
            verdict = "BENIGN / VERIFIED SAFE"
            action = "No active indicators of compromise. Mark case closed."

        final_report = {
            "Analysis_Timestamp": str(datetime.now() if 'datetime' in globals() else "2026-09-30"),
            "Email_Metadata": self.metadata,
            "Live_Threat_Intelligence": self.threat_intel,
            "SOC_Triage_Verdict": verdict,
            "Recommended_Incident_Response": action
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=4)
        print(f"[+] Incident report output saved to local directory: {output_path}")


# Executable Sandbox for Verification
if __name__ == "__main__":
    # 1. Generate a mock raw phishing email header file (.eml format)
    mock_email_raw = """From: security-update@paypal-verify-alert.com
To: victim-user@enterprise-corp.com
Subject: CRITICAL: Account Access Restricted - Action Required
Date: Wed, 30 Sep 2026 10:14:22 +0100
Received: from ://enterprise-corp.com (192.168.1.10) by internal-server.local; Wed, 30 Sep 2026
Received: from tracking-server.attacker-node.net (185.220.101.3) by ://enterprise-corp.com; Wed, 30 Sep 2026"""

    with open("suspicious_email.eml", "w", encoding="utf-8") as f:
        f.write(mock_email_raw.strip())

    # 2. Fire the engine pipeline
    # Paste your live AbuseIPDB key string inside the quotes below
    MY_API_KEY = "GENERATED_API_KEY" 
    
    analyser = PhishingEmailAnalyser("suspicious_email.eml", api_key=MY_API_KEY)
    analyser.parse_email_headers()
    analyser.fetch_threat_intelligence()
    analyser.compile_triage_verdict()
