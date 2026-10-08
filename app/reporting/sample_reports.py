"""
sample_reports.py
===================

Generates 5 realistic sample incident reports demonstrating the full
reporting pipeline (report_generator + executive_summary +
threat_intelligence + json_export), covering:

    1. Compromised Account
    2. Malware Infection
    3. Phishing Campaign
    4. Insider Threat
    5. Credential Dump

Each generated report includes: a timeline, a numeric risk score/level,
the ATT&CK stage chain, and a business-readable executive summary.

Run directly (`python sample_reports.py`) to write all 5 reports as
formatted JSON files into an `output/` folder alongside this file.
"""

import os
from typing import Any, Dict, List

from . import threat_intelligence as ti
from .executive_summary import create_executive_summary
from .json_export import export_reports
from .report_generator import generate_incident_report

# ---------------------------------------------------------------------------
# Raw sample incidents (as they would arrive from the detection/correlation
# engine upstream of this reporting module).
# ---------------------------------------------------------------------------

SAMPLE_INCIDENTS: List[Dict[str, Any]] = [
    # 1. Compromised Account
    {
        "incident_id": "INC-2001",
        "title": "Compromised Employee Account - jdoe",
        "description": "Correlated alerts indicate a compromised employee account with anomalous access patterns.",
        "affected_entities": ["user:jdoe", "host:WKS-102"],
        "events": [
            {
                "timestamp": "2026-08-01T02:14:00Z",
                "technique": "login_anomaly",
                "description": "Login from unusual geolocation (Eastern Europe) outside business hours",
            },
            {
                "timestamp": "2026-08-01T02:19:00Z",
                "technique": "powershell_exec",
                "description": "Obfuscated PowerShell command executed on WKS-102",
            },
            {
                "timestamp": "2026-08-01T02:26:00Z",
                "technique": "privilege_escalation",
                "description": "Local admin group modified to include jdoe",
            },
        ],
    },
    # 2. Malware Infection
    {
        "incident_id": "INC-2002",
        "title": "Malware Infection on Finance Workstation",
        "description": "Endpoint detection flagged ransomware-style behavior on a finance department workstation.",
        "affected_entities": ["host:FIN-WKS-07", "host:FIN-SHARE-01"],
        "events": [
            {
                "timestamp": "2026-08-03T09:02:00Z",
                "technique": "malicious_attachment",
                "description": "User opened a malicious invoice attachment",
            },
            {
                "timestamp": "2026-08-03T09:03:30Z",
                "technique": "macro_execution",
                "description": "Office macro spawned a child process",
            },
            {
                "timestamp": "2026-08-03T09:05:00Z",
                "technique": "scheduled_task",
                "description": "Persistence established via scheduled task 'UpdaterSvc'",
            },
            {
                "timestamp": "2026-08-03T09:12:00Z",
                "technique": "file_encryption",
                "description": "Mass file encryption detected on mapped network share FIN-SHARE-01",
            },
        ],
    },
    # 3. Phishing Campaign
    {
        "incident_id": "INC-2003",
        "title": "Phishing Campaign Targeting HR Department",
        "description": "A phishing email campaign targeted multiple HR staff with credential-harvesting links.",
        "affected_entities": ["user:mrivera", "user:asingh", "user:kwong"],
        "events": [
            {
                "timestamp": "2026-08-05T13:40:00Z",
                "technique": "phishing_email",
                "description": "Phishing email with spoofed IT helpdesk sender delivered to 3 HR mailboxes",
            },
            {
                "timestamp": "2026-08-05T13:47:00Z",
                "technique": "malicious_link",
                "description": "Two recipients clicked the embedded credential-harvesting link",
            },
            {
                "timestamp": "2026-08-05T13:52:00Z",
                "technique": "login_anomaly",
                "description": "Successful login using harvested credentials from a new device",
            },
        ],
    },
    # 4. Insider Threat
    {
        "incident_id": "INC-2004",
        "title": "Insider Threat - Anomalous Data Staging by Departing Employee",
        "description": "A soon-to-depart employee was observed staging and exporting large volumes of sensitive data.",
        "affected_entities": ["user:tlee", "host:TLEE-LAPTOP"],
        "events": [
            {
                "timestamp": "2026-08-10T18:05:00Z",
                "technique": "sensitive_file_read",
                "description": "Bulk access to confidential client contract repository outside normal duties",
            },
            {
                "timestamp": "2026-08-10T18:22:00Z",
                "technique": "file_staging",
                "description": "Approximately 4.2 GB of files copied to a local staging folder",
            },
            {
                "timestamp": "2026-08-10T18:40:00Z",
                "technique": "cloud_upload",
                "description": "Staged files uploaded to a personal cloud storage account",
            },
        ],
        "root_cause": "Departing employee exfiltrated confidential client data ahead of resignation.",
    },
    # 5. Credential Dump
    {
        "incident_id": "INC-2005",
        "title": "Credential Dump on Domain Controller",
        "description": "Suspicious process accessed LSASS memory on a domain controller, consistent with credential dumping.",
        "affected_entities": ["host:DC-01", "domain:corp.hawkeye.local"],
        "events": [
            {
                "timestamp": "2026-08-14T04:11:00Z",
                "technique": "lsass_access",
                "description": "Unusual process opened a handle to LSASS.exe with dumping-capable access rights",
            },
            {
                "timestamp": "2026-08-14T04:12:15Z",
                "technique": "credential_dump",
                "description": "Credential dumping tool signature detected in process memory",
            },
            {
                "timestamp": "2026-08-14T04:20:00Z",
                "technique": "pass_the_hash",
                "description": "Dumped hash reused to authenticate to a second domain controller",
            },
        ],
    },
]


def generate_all_sample_reports() -> Dict[str, Dict[str, Any]]:
    """
    Generate the full set of 5 sample incident reports.

    Each returned report is the standard report_generator output,
    additionally enriched with:
        - "attack_chain": human-readable ATT&CK stage chain string
        - "attack_stages": list of unique ATT&CK stage names
        - "executive_summary": business-readable summary string

    Returns:
        Mapping of {incident_id: enriched_report_dict}.
    """
    reports: Dict[str, Dict[str, Any]] = {}

    for incident in SAMPLE_INCIDENTS:
        report = generate_incident_report(incident)

        technique_keys = [event.get("technique", "") for event in incident.get("events", [])]
        report["attack_chain"] = ti.get_attack_chain_summary(technique_keys)
        report["attack_stages"] = ti.map_techniques_to_stages(technique_keys)
        report["executive_summary"] = create_executive_summary(incident)

        reports[report["incident_id"]] = report

    return reports


def write_sample_reports_to_disk(output_dir: str = None) -> Dict[str, str]:
    """
    Generate all sample reports and write each as a JSON file.

    Args:
        output_dir: Directory to write into. Defaults to an "output"
            folder located alongside this file.

    Returns:
        Mapping of {incident_id: absolute_written_path}.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

    reports = generate_all_sample_reports()
    return export_reports(reports, output_dir)


if __name__ == "__main__":
    written = write_sample_reports_to_disk()
    print(f"Generated {len(written)} sample reports:")
    for incident_id, path in written.items():
        print(f"  - {incident_id}: {path}")
