"""
scenarios.py
-------------
Defines the synthetic attack-chain logic for each supported SOC scenario.
Each scenario function returns a list of alert dicts (5-12 alerts) built
via event_generator.build_alert, following a plausible attack progression
with MITRE ATT&CK technique tags for realism.

Supported scenarios:
    - credential_theft
    - phishing
    - malware
    - insider_threat
    - ransomware
"""

from .event_generator import (
    make_user, make_device, make_internal_ip, make_external_ip,
    make_incident_id, timestamp_sequence, random_start_time, build_alert,
)

SCENARIO_NAMES = [
    "credential_theft",
    "phishing",
    "malware",
    "insider_threat",
    "ransomware",
]


def _alert_count(rng, low=7, high=10):
    """Pick how many alerts (7-10) this scenario instance will produce."""
    return rng.randint(low, high)


def generate_credential_theft(rng, incident_id=None, start_time=None):
    """
    Attack chain: repeated failed logins -> password spray/brute force ->
    successful login from anomalous location -> MFA bypass -> privilege
    use -> credential dumping -> lateral movement attempt.
    """
    incident_id = incident_id or make_incident_id(rng)
    user = make_user(rng)
    device = make_device(rng)
    attacker_ip = make_external_ip(rng)
    internal_ip = make_internal_ip(rng)
    n = _alert_count(rng, 7, 10)
    start = start_time or random_start_time(rng)
    times = timestamp_sequence(rng, start, n, min_gap_seconds=45, max_gap_seconds=150, max_total_window_seconds=1500)

    steps = [
        ("Failed Login", f"Failed authentication attempt for {user['username']} from {attacker_ip}", "T1110", "Medium"),
        ("Failed Login", f"Repeated failed authentication for {user['username']} from {attacker_ip}", "T1110", "Medium"),
        ("Failed Login", f"Account lockout threshold approaching for {user['username']}", "T1110", "High"),
        ("Anomalous Login Success", f"Successful login for {user['username']} from unusual geolocation ({attacker_ip})", "T1078", "High"),
        ("Impossible Travel", f"Impossible travel detected for {user['username']}: prior session on {internal_ip}", "T1078", "Critical"),
        ("MFA Bypass Attempt", f"MFA challenge repeatedly denied then bypassed for {user['username']}", "T1111", "Critical"),
        ("Privilege Use", f"Elevated privilege token used by {user['username']} on {device['hostname']}", "T1078.004", "High"),
        ("Credential Dumping", f"LSASS memory access detected on {device['hostname']}", "T1003", "Critical"),
        ("Lateral Movement", f"New authenticated session from {device['hostname']} to adjacent host", "T1021", "High"),
        ("New Access Token", f"New OAuth/API token issued for {user['username']} from {attacker_ip}", "T1550", "High"),
        ("Suspicious Mailbox Rule", f"New forwarding rule created in {user['username']}'s mailbox", "T1114.003", "Medium"),
        ("Account Disabled", f"SOC analyst disabled account {user['username']} pending investigation", "T1531", "Low"),
    ]

    chosen = steps[:n]
    alerts = []
    for ts, (event_type, desc, technique, sev) in zip(times, chosen):
        alerts.append(build_alert(
            timestamp=ts, incident_id=incident_id, scenario="credential_theft",
            user=user, device=device, src_ip=attacker_ip, dst_ip=internal_ip,
            event_type=event_type, description=desc, severity=sev,
            mitre_technique=technique,
        ))
    return alerts


def generate_phishing(rng, incident_id=None, start_time=None):
    """
    Attack chain: phishing email delivered -> link clicked -> credential
    harvesting page submitted -> malicious attachment opened -> macro
    execution -> outbound C2 beacon.
    """
    incident_id = incident_id or make_incident_id(rng)
    user = make_user(rng)
    device = make_device(rng)
    sender_ip = make_external_ip(rng)
    c2_ip = make_external_ip(rng)
    internal_ip = make_internal_ip(rng)
    n = _alert_count(rng, 7, 10)
    start = start_time or random_start_time(rng)
    times = timestamp_sequence(rng, start, n, min_gap_seconds=45, max_gap_seconds=150, max_total_window_seconds=1500)

    steps = [
        ("Phishing Email Delivered", f"Email with suspicious sender reputation delivered to {user['username']}", "T1566.001", "Medium"),
        ("URL Click", f"{user['username']} clicked link in flagged email from {sender_ip}", "T1204.001", "Medium"),
        ("Credential Harvesting Page", "User submitted credentials to a known phishing domain", "T1566.002", "High"),
        ("Attachment Opened", f"Malicious attachment opened on {device['hostname']}", "T1204.002", "High"),
        ("Macro Execution", f"Office macro execution spawned a child process on {device['hostname']}", "T1059.005", "High"),
        ("Suspicious Process", f"powershell.exe spawned from winword.exe on {device['hostname']}", "T1059.001", "Critical"),
        ("Outbound C2 Beacon", f"Periodic beaconing detected from {device['hostname']} to {c2_ip}", "T1071", "Critical"),
        ("DNS Anomaly", f"DNS query to newly registered domain from {device['hostname']}", "T1071.004", "Medium"),
        ("Mail Forward Rule", f"Auto-forward rule created in {user['username']}'s mailbox to an external address", "T1114.003", "High"),
        ("Password Reset Attempt", f"Self-service password reset attempted for {user['username']}", "T1098", "Medium"),
        ("Email Reported", "A colleague reported a similar phishing email to the SOC", "T1566.001", "Low"),
        ("Sandbox Detonation", "Attachment detonated in sandbox and confirmed malicious", "T1204.002", "High"),
    ]
    chosen = steps[:n]
    alerts = []
    for ts, (event_type, desc, technique, sev) in zip(times, chosen):
        dst = c2_ip if event_type in ("Outbound C2 Beacon", "DNS Anomaly") else internal_ip
        alerts.append(build_alert(
            timestamp=ts, incident_id=incident_id, scenario="phishing",
            user=user, device=device, src_ip=sender_ip, dst_ip=dst,
            event_type=event_type, description=desc, severity=sev,
            mitre_technique=technique,
        ))
    return alerts


def generate_malware(rng, incident_id=None, start_time=None):
    """
    Attack chain: malicious file dropped -> AV/EDR detection -> process
    injection -> persistence established -> outbound C2 -> attempted
    lateral spread -> containment.
    """
    incident_id = incident_id or make_incident_id(rng)
    user = make_user(rng)
    device = make_device(rng)
    c2_ip = make_external_ip(rng)
    internal_ip = make_internal_ip(rng)
    n = _alert_count(rng, 7, 10)
    start = start_time or random_start_time(rng)
    times = timestamp_sequence(rng, start, n, min_gap_seconds=45, max_gap_seconds=150, max_total_window_seconds=1500)

    steps = [
        ("File Dropped", f"Suspicious executable dropped in temp directory on {device['hostname']}", "T1105", "Medium"),
        ("AV Detection", f"Endpoint AV flagged file as generic trojan on {device['hostname']}", "T1204", "High"),
        ("Process Injection", f"Reflective DLL injection detected in explorer.exe on {device['hostname']}", "T1055", "Critical"),
        ("Registry Persistence", f"New Run key persistence created on {device['hostname']}", "T1547.001", "High"),
        ("Scheduled Task Created", f"Suspicious scheduled task created on {device['hostname']}", "T1053.005", "High"),
        ("Outbound C2 Beacon", f"Beaconing to {c2_ip} detected from {device['hostname']}", "T1071", "Critical"),
        ("Disabled Security Tooling", f"Attempt to disable EDR service on {device['hostname']}", "T1562.001", "Critical"),
        ("Suspicious Network Scan", f"Internal port scan originating from {device['hostname']}", "T1046", "High"),
        ("Lateral Spread Attempt", f"SMB write attempt from {device['hostname']} to an adjacent host", "T1021.002", "High"),
        ("File Quarantined", f"EDR quarantined malicious binary on {device['hostname']}", "T1204", "Low"),
        ("Host Isolated", f"SOC isolated {device['hostname']} from the network", "T1562", "Low"),
        ("Hash Match - Known Malware Family", "File hash matched a known malware family in threat intel feed", "T1588.001", "Critical"),
    ]
    chosen = steps[:n]
    alerts = []
    for ts, (event_type, desc, technique, sev) in zip(times, chosen):
        alerts.append(build_alert(
            timestamp=ts, incident_id=incident_id, scenario="malware",
            user=user, device=device, src_ip=internal_ip, dst_ip=c2_ip,
            event_type=event_type, description=desc, severity=sev,
            mitre_technique=technique,
        ))
    return alerts


def generate_insider_threat(rng, incident_id=None, start_time=None):
    """
    Attack chain: after-hours access -> abnormal data access volume ->
    sensitive file access -> bulk download -> removable media / personal
    cloud upload -> data staging -> HR correlation -> access revoked.
    """
    incident_id = incident_id or make_incident_id(rng)
    user = make_user(rng)
    device = make_device(rng)
    internal_ip = make_internal_ip(rng)
    external_ip = make_external_ip(rng)
    n = _alert_count(rng, 7, 10)
    start = start_time or random_start_time(rng)
    times = timestamp_sequence(rng, start, n, min_gap_seconds=45, max_gap_seconds=150, max_total_window_seconds=1500)

    steps = [
        ("After-Hours Access", f"{user['username']} logged in outside normal working hours", "T1078", "Low"),
        ("Abnormal Data Access Volume", f"{user['username']} accessed significantly more files than baseline", "T1005", "Medium"),
        ("Sensitive File Access", f"{user['username']} accessed a restricted HR/finance share", "T1005", "High"),
        ("Bulk Download", f"Large volume download ({rng.randint(500, 5000)} files) by {user['username']}", "T1030", "High"),
        ("Removable Media Use", f"USB mass storage device connected to {device['hostname']}", "T1052.001", "High"),
        ("Personal Cloud Upload", f"Upload to a personal cloud storage domain detected from {device['hostname']}", "T1567.002", "Critical"),
        ("Data Staging", f"Archive file created prior to likely exfiltration on {device['hostname']}", "T1074.001", "High"),
        ("Unauthorized Mailbox Access", f"{user['username']} accessed another employee's mailbox without authorization", "T1114", "Medium"),
        ("Badge/Login Mismatch", f"Login recorded for {user['username']} without a corresponding badge entry", "T1078", "Medium"),
        ("HR Flag Correlation", f"SOC correlated activity with a pending resignation notice for {user['username']}", "T1078", "High"),
        ("Print Spike", f"Unusual spike in print jobs containing 'confidential' markings by {user['username']}", "T1005", "Medium"),
        ("Account Access Revoked", f"IT revoked {user['username']}'s access pending investigation", "T1531", "Low"),
    ]
    chosen = steps[:n]
    alerts = []
    for ts, (event_type, desc, technique, sev) in zip(times, chosen):
        dst = external_ip if event_type == "Personal Cloud Upload" else internal_ip
        alerts.append(build_alert(
            timestamp=ts, incident_id=incident_id, scenario="insider_threat",
            user=user, device=device, src_ip=internal_ip, dst_ip=dst,
            event_type=event_type, description=desc, severity=sev,
            mitre_technique=technique,
        ))
    return alerts


def generate_ransomware(rng, incident_id=None, start_time=None):
    """
    Attack chain: initial access artifact -> credential access -> disabling
    backups/shadow copies -> mass file encryption -> ransom note drop ->
    C2 confirmation -> lateral encryption spread -> containment.
    """
    incident_id = incident_id or make_incident_id(rng)
    user = make_user(rng)
    device = make_device(rng)
    c2_ip = make_external_ip(rng)
    internal_ip = make_internal_ip(rng)
    n = _alert_count(rng, 7, 10)
    start = start_time or random_start_time(rng)
    times = timestamp_sequence(rng, start, n, min_gap_seconds=45, max_gap_seconds=150, max_total_window_seconds=1500)

    steps = [
        ("Initial Access Artifact", f"Suspicious binary executed on {device['hostname']} via {user['username']}'s session", "T1204", "High"),
        ("Credential Access", f"Credential dumping tool detected on {device['hostname']}", "T1003", "Critical"),
        ("Shadow Copy Deletion", f"vssadmin used to delete shadow copies on {device['hostname']}", "T1490", "Critical"),
        ("Backup Service Disabled", f"Backup agent service stopped on {device['hostname']}", "T1489", "Critical"),
        ("Mass File Modification", f"Abnormal rate of file rename/encryption operations on {device['hostname']}", "T1486", "Critical"),
        ("File Extension Change", f"Thousands of files renamed with an unknown extension on {device['hostname']}", "T1486", "Critical"),
        ("Ransom Note Dropped", f"Ransom note file 'README_DECRYPT.txt' created on {device['hostname']}", "T1491.001", "Critical"),
        ("Outbound C2 Confirmation", f"Encryption key exchange beacon to {c2_ip} from {device['hostname']}", "T1071", "Critical"),
        ("Lateral Encryption Spread", f"Encryption activity detected spreading to network share from {device['hostname']}", "T1021.002", "Critical"),
        ("SOC Containment Action", f"SOC isolated {device['hostname']} and disabled network share access", "T1489", "Medium"),
        ("Backup Integrity Check", "Offline backup integrity verified as unaffected", "T1490", "Low"),
        ("Incident Escalation", f"Incident escalated to executive/legal team for {incident_id}", "T1486", "High"),
    ]
    chosen = steps[:n]
    alerts = []
    for ts, (event_type, desc, technique, sev) in zip(times, chosen):
        alerts.append(build_alert(
            timestamp=ts, incident_id=incident_id, scenario="ransomware",
            user=user, device=device, src_ip=internal_ip, dst_ip=c2_ip,
            event_type=event_type, description=desc, severity=sev,
            mitre_technique=technique,
        ))
    return alerts


SCENARIO_GENERATORS = {
    "credential_theft": generate_credential_theft,
    "phishing": generate_phishing,
    "malware": generate_malware,
    "insider_threat": generate_insider_threat,
    "ransomware": generate_ransomware,
}
