# User Guide: Digital Incident Response System
## A Step-by-Step Guide for Incident Investigators

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Running Your First Analysis](#running-your-first-analysis)
3. [Preparing Evidence](#preparing-evidence)
4. [Interpreting Results](#interpreting-results)
5. [Advanced Usage](#advanced-usage)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Basic understanding of digital forensics
- Familiarity with log file formats

### Installation

No installation required! The system is ready to use:

```bash
# Navigate to the system directory
cd incident_response_system/

# Run the demonstration
python demo.py
```

### Quick Start (5 Minutes)

The fastest way to see the system in action:

```bash
# Run the demo with sample data
python demo.py

# Open the generated timeline
# File: output/timeline_visualization.html
```

---

## Running Your First Analysis

### Option 1: Use Sample Data (Recommended for Learning)

```bash
# Generate and analyze sample incident data
python demo.py
```

**What happens:**
1. System generates realistic attack scenario
2. Creates Windows, Network, and USB logs
3. Analyzes the incident
4. Generates reports and visualizations

**Expected output:**
```
[1] Generating Sample Forensic Data...
[2] Initializing Incident Response System...
[3] Ingesting Forensic Evidence...
[4] Verifying Evidence Integrity...
[5] Reconstructing Timeline...
[6] Generated Output Files:
    ✓ Interactive Timeline: output/timeline_visualization.html
    ✓ Forensic Report:      output/forensic_report.txt
    ✓ JSON Export:          output/timeline_export.json
```

### Option 2: Analyze Your Own Evidence

#### Step 1: Prepare Your Evidence Files

Create JSON files in the `logs/` directory:

```bash
logs/
├── windows_events.json
├── network_traffic.json
└── usb_activity.json
```

#### Step 2: Create Analysis Script

```python
# my_analysis.py
from incident_response_system import IncidentResponseSystem
import json

# Define case details
case_details = {
    'case_id': 'IR-2026-002',
    'incident_type': 'Unauthorized Access Investigation',
    'organization': 'Your Company Name',
    'investigator': 'Your Name',
    'executive_summary': 'Brief description of the incident'
}

# Initialize system
system = IncidentResponseSystem('IR-2026-002', case_details)

# Register evidence files
system.add_evidence_file('./logs/windows_events.json')
system.add_evidence_file('./logs/network_traffic.json')
system.add_evidence_file('./logs/usb_activity.json')

# Load data
with open('./logs/windows_events.json') as f:
    windows_logs = json.load(f)

with open('./logs/network_traffic.json') as f:
    network_logs = json.load(f)

with open('./logs/usb_activity.json') as f:
    usb_logs = json.load(f)

# Ingest and analyze
system.ingest_forensic_data(
    windows_logs=windows_logs,
    network_logs=network_logs,
    usb_logs=usb_logs
)

# Generate reports
results = system.analyze_and_report('./output')

print(f"Analysis complete! {len(results['timeline'])} events analyzed.")
```

#### Step 3: Run Analysis

```bash
python my_analysis.py
```

---

## Preparing Evidence

### Windows Event Logs

#### From Windows Event Viewer

1. **Export Security Logs**:
   - Open Event Viewer (eventvwr.msc)
   - Navigate to Windows Logs → Security
   - Right-click → Save All Events As → CSV format
   
2. **Convert CSV to JSON**:
   ```python
   import csv
   import json
   from datetime import datetime
   
   def convert_csv_to_json(csv_file, json_file):
       events = []
       with open(csv_file, 'r') as f:
           reader = csv.DictReader(f)
           for row in reader:
               event = {
                   'timestamp': row['Date and Time'],
                   'event_id': row['Event ID'],
                   'level': row['Level'],
                   'channel': 'Security',
                   'message': row['Task Category'],
                   'computer': row['Computer'],
                   'user': row.get('User', 'SYSTEM'),
                   'process_id': 0
               }
               events.append(event)
       
       with open(json_file, 'w') as f:
           json.dump(events, f, indent=2)
   
   convert_csv_to_json('security.csv', 'windows_events.json')
   ```

#### From PowerShell

```powershell
# Export last 1000 security events
Get-WinEvent -FilterHashtable @{
    LogName='Security';
    ID=4624,4672,4688,4698,4634
} -MaxEvents 1000 | 
ConvertTo-Json | 
Out-File windows_events.json
```

### Network Traffic Logs

#### From Firewall Logs

**Example: Converting pfSense logs**

```python
def parse_pfsense_log(log_line):
    # Parse pfSense format: timestamp,action,protocol,src,dst,src_port,dst_port
    fields = log_line.split(',')
    
    return {
        'timestamp': fields[0],
        'action': fields[1],
        'protocol': fields[2],
        'src_ip': fields[3],
        'dst_ip': fields[4],
        'src_port': int(fields[5]),
        'dst_port': int(fields[6]),
        'bytes': int(fields[7]) if len(fields) > 7 else 0,
        'severity': 'Information'
    }

events = []
with open('firewall.log') as f:
    for line in f:
        if line.strip():
            events.append(parse_pfsense_log(line))

with open('network_traffic.json', 'w') as f:
    json.dump(events, f, indent=2)
```

#### From PCAP Files (using tshark)

```bash
# Extract network flows from PCAP
tshark -r capture.pcap -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e frame.len \
    -E separator=, > network.csv

# Convert to JSON (Python script needed)
```

### USB Device Activity

#### From Windows Registry

```python
import winreg
import json
from datetime import datetime

def extract_usb_devices():
    events = []
    key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                # Extract device information
                # ... (implementation details)
                i += 1
            except WindowsError:
                break
    except:
        pass
    
    return events

devices = extract_usb_devices()
with open('usb_activity.json', 'w') as f:
    json.dump(devices, f, indent=2)
```

#### From System Logs

```python
# Extract USB events from Windows System log
Get-WinEvent -FilterHashtable @{
    LogName='System';
    ProviderName='Microsoft-Windows-DriverFrameworks-UserMode'
} | Where-Object {$_.Message -like "*USB*"} |
ConvertTo-Json | Out-File usb_activity.json
```

---

## Interpreting Results

### Understanding the Timeline Visualization

#### Opening the Timeline

```bash
# Open in your default browser
open output/timeline_visualization.html

# Or navigate directly
firefox output/timeline_visualization.html
```

#### Timeline Features

1. **Color Coding**:
   - 🔴 **Red**: Critical events (data exfiltration, critical vulnerabilities)
   - 🟠 **Orange**: High severity (privilege escalation, suspicious access)
   - 🟡 **Yellow**: Warning (authentication failures, blocked attempts)
   - 🔵 **Blue**: Informational (normal operations)

2. **Event Cards**:
   - **Timestamp**: Exact time of occurrence
   - **Source**: Log origin (Windows/Network/USB)
   - **Description**: Human-readable summary
   - **Details**: Technical metadata
   - **IOC Tags**: Security indicators
   - **Attack Stage**: MITRE ATT&CK classification

3. **Filtering**:
   - Use checkboxes to show/hide severity levels
   - Focus on critical events first
   - Expand to see full context

#### Reading the Timeline

**Example Analysis Workflow**:

```
1. Start with Critical events
   → Identify data exfiltration attempts
   → Note timestamps and involved systems

2. Look at preceding High events
   → Check for privilege escalation
   → Identify persistence mechanisms

3. Trace back to Initial Access
   → Find how attacker entered
   → Identify compromised credentials

4. Follow forward to Exfiltration
   → Determine what data was accessed
   → Identify exfiltration channels
```

### Reading the Forensic Report

#### Report Sections

**1. Case Information**
- Case ID, date, investigator
- Basic metadata

**2. Executive Summary**
- High-level overview
- Key findings
- Impact assessment

**3. Evidence Sources**
- List of analyzed files
- SHA-256 and MD5 hashes
- Collection timestamps

**4. Attack Stage Analysis**
```
Initial Access              : 31 events
Privilege Escalation        :  7 events
Persistence                 :  7 events
Exfiltration               :  5 events
```
*Interpretation*: Attacker gained initial access, escalated privileges, established persistence, and exfiltrated data.

**5. Severity Distribution**
```
Critical                    :  8 events
High                        :  2 events
Warning                     : 25 events
Information                 : 41 events
```
*Interpretation*: 8 critical events requiring immediate attention.

**6. Critical Events Timeline**
- Chronological list of important events
- Detailed descriptions
- IOC tags and attack stages

**7. Key Findings**
- Automated pattern detection
- Highlighted threats
- Evidence of compromise

**8. Conclusions and Recommendations**
- Summary of attack
- Recommended actions
- Remediation steps

### Understanding IOC Tags

| IOC Tag | Meaning | Action Required |
|---------|---------|-----------------|
| `authentication` | Login event | Review user credentials |
| `privilege_escalation` | Elevated access | Check for unauthorized admin access |
| `process_execution` | Program run | Verify legitimate processes |
| `persistence` | Scheduled task/startup | Remove unauthorized persistence |
| `remote_access` | RDP/SSH connection | Verify authorized access |
| `external_communication` | Internet connection | Check for C2 communication |
| `data_exfiltration` | Large data transfer | Identify stolen data |
| `removable_media` | USB device | Track physical data theft |

---

## Advanced Usage

### Custom Attack Stage Definitions

```python
from incident_response_system import AttackStageClassifier

# Add custom stage
AttackStageClassifier.ATTACK_STAGES['Data Destruction'] = [
    'file_deletion', 'disk_wipe', 'ransomware'
]

# Custom classification
def custom_classify(event):
    if 'ransomware' in event.description.lower():
        event.ioc_tags.append('ransomware')
        event.severity = 'Critical'
    return event
```

### Filtering Timeline by Criteria

```python
# Get only critical events
critical_events = [e for e in timeline if e.severity == 'Critical']

# Get events in time range
from datetime import datetime, timedelta

start_time = datetime(2026, 2, 9, 10, 0, 0)
end_time = start_time + timedelta(hours=1)

filtered = [e for e in timeline 
            if start_time <= e.timestamp <= end_time]

# Get events by attack stage
exfiltration_events = [e for e in timeline 
                       if e.attack_stage == 'Exfiltration']
```

### Exporting Specific Event Subsets

```python
import json

# Export only USB events
usb_events = [e for e in timeline if e.source == 'USB Device Activity']

with open('usb_events_only.json', 'w') as f:
    json.dump([e.to_dict() for e in usb_events], f, indent=2)

# Export events by time period
morning_events = [e for e in timeline 
                  if e.timestamp.hour < 12]
```

### Custom Report Templates

```python
def generate_executive_summary(timeline):
    critical = len([e for e in timeline if e.severity == 'Critical'])
    stages = set(e.attack_stage for e in timeline if e.attack_stage)
    
    summary = f"""
EXECUTIVE SUMMARY
-----------------
Total Events: {len(timeline)}
Critical Events: {critical}
Attack Stages: {len(stages)}
Duration: {timeline[-1].timestamp - timeline[0].timestamp}

IMMEDIATE ACTIONS REQUIRED:
1. Isolate affected systems
2. Reset compromised credentials
3. Review {critical} critical events
"""
    return summary
```

---

## Best Practices

### Evidence Collection

✅ **DO**:
- Calculate hashes immediately after collection
- Use write-blockers for disk imaging
- Document collection process
- Maintain chain of custody
- Create forensic copies, never work on originals
- Timestamp all activities

❌ **DON'T**:
- Modify original evidence
- Skip hash verification
- Work without documentation
- Trust timestamps without verification
- Delete evidence prematurely

### Analysis Workflow

**Recommended Order**:

1. **Preparation**
   - Verify evidence integrity (check hashes)
   - Review case details
   - Set analysis goals

2. **Initial Assessment**
   - Run automated analysis
   - Review attack summary
   - Identify critical events

3. **Deep Dive**
   - Examine critical events first
   - Correlate across sources
   - Build attack timeline

4. **Verification**
   - Cross-reference findings
   - Verify with original logs
   - Document assumptions

5. **Reporting**
   - Generate comprehensive report
   - Include evidence hashes
   - Make clear recommendations

### Timeline Analysis Tips

1. **Start with the Big Picture**
   - Review attack stage distribution
   - Identify peak activity periods
   - Note unusual patterns

2. **Focus on Anomalies**
   - Off-hours activity
   - Unusual user accounts
   - Large data transfers
   - External IP connections

3. **Correlate Events**
   - Match login with network activity
   - Connect process execution with file access
   - Link USB insertion with data transfers

4. **Look for Patterns**
   - Repeated failed logins → brute force
   - Sequential privilege escalation → planned attack
   - Multiple exfiltration methods → sophisticated threat

---

## Troubleshooting

### Common Issues

#### 1. "File not found" Error

**Problem**: Evidence files not in correct location

**Solution**:
```bash
# Check file locations
ls -la logs/

# Verify file paths in script
system.add_evidence_file('./logs/windows_events.json')  # Correct path?
```

#### 2. Timestamp Parsing Errors

**Problem**: Non-ISO 8601 timestamp format

**Solution**:
```python
# Convert timestamps before analysis
from datetime import datetime

def normalize_timestamp(ts_string):
    # Try multiple formats
    formats = [
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%m/%d/%Y %H:%M:%S'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(ts_string, fmt).isoformat()
        except:
            continue
    
    raise ValueError(f"Cannot parse: {ts_string}")
```

#### 3. Missing IOC Tags

**Problem**: Events not being tagged as suspicious

**Solution**:
```python
# Add custom IOC detection
def add_custom_iocs(event):
    # Check for suspicious usernames
    if event.details.get('user') in ['admin', 'root', 'administrator']:
        event.ioc_tags.append('privileged_account')
    
    # Check for suspicious processes
    suspicious_procs = ['powershell.exe', 'cmd.exe', 'psexec.exe']
    if any(proc in event.description.lower() for proc in suspicious_procs):
        event.ioc_tags.append('suspicious_process')
    
    return event
```

#### 4. Hash Verification Failures

**Problem**: Hashes don't match after analysis

**Cause**: File was modified during analysis

**Solution**:
- Work on copies, not originals
- Check file permissions (read-only)
- Verify no auto-save features are active

#### 5. Large Dataset Performance

**Problem**: Analysis taking too long

**Solution**:
```python
# Process in chunks
def process_large_dataset(log_file, chunk_size=10000):
    events = []
    with open(log_file) as f:
        data = json.load(f)
        
    # Process in chunks
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        events.extend(process_chunk(chunk))
    
    return events
```

---

## Case Study: Investigating a Data Breach

### Scenario

You've been called to investigate a suspected data breach at Acme Corporation. You have access to:
- Windows Security Event Logs (3 days)
- Firewall logs (3 days)
- USB device activity logs (3 days)

### Investigation Steps

#### Phase 1: Evidence Collection

```bash
# 1. Create case directory
mkdir case-IR-2026-002
cd case-IR-2026-002

# 2. Copy evidence files
cp /path/to/evidence/* ./logs/

# 3. Calculate hashes
sha256sum logs/* > evidence_hashes.txt

# 4. Document collection
echo "Evidence collected on $(date)" > collection_log.txt
echo "Collected by: Your Name" >> collection_log.txt
```

#### Phase 2: Initial Analysis

```python
# Run automated analysis
python demo.py  # Or your custom script

# Review outputs
# 1. Open timeline_visualization.html
# 2. Read forensic_report.txt
# 3. Note critical events
```

#### Phase 3: Timeline Analysis

**Key Questions**:
1. When did the breach start?
2. How did the attacker gain access?
3. What systems were compromised?
4. What data was accessed/stolen?
5. How did data leave the network?

**Analysis Process**:

```
Timeline Review:
├─ 2026-02-09 08:45 - Initial Access
│  └─ External RDP connection from 198.51.100.89
│     └─ User: suspicious-user@external.com
│
├─ 2026-02-09 08:50 - Privilege Escalation
│  └─ Special privileges assigned (Event 4672)
│     └─ User elevated to administrator
│
├─ 2026-02-09 09:20 - Data Collection
│  └─ Multiple large file accesses
│     └─ Sensitive directories accessed
│
├─ 2026-02-09 09:25 - Exfiltration (Network)
│  └─ 15MB transferred to 203.0.113.45:443
│     └─ HTTPS encrypted channel
│
└─ 2026-02-09 09:35 - Exfiltration (USB)
   └─ Kingston DataTraveler connected
      └─ Large data transfer detected
```

#### Phase 4: Reporting

Use the generated forensic report as a base:
1. Add specific findings from your analysis
2. Include screenshots from timeline
3. Document all IOCs found
4. Make clear recommendations
5. List compromised systems and data

---

## Additional Resources

### MITRE ATT&CK Framework
- Website: https://attack.mitre.org/
- Learn attack techniques and tactics
- Map your findings to ATT&CK

### NIST Guidelines
- SP 800-86: Guide to Integrating Forensic Techniques
- SP 800-61: Computer Security Incident Handling Guide

### Tools Compatibility
This system complements:
- Splunk (log analysis)
- ELK Stack (log aggregation)
- Wireshark (network analysis)
- Autopsy (disk forensics)
- Volatility (memory analysis)

---

## Quick Reference

### Common Commands

```bash
# Run demo
python demo.py

# Generate sample data only
python generate_sample_data.py

# View help
python demo.py --help
```

### File Locations

```
Input:
  logs/windows_events.json
  logs/network_traffic.json
  logs/usb_activity.json

Output:
  output/timeline_visualization.html
  output/forensic_report.txt
  output/timeline_export.json
```

### Key Event IDs (Windows)

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Account logoff |
| 4648 | Logon using explicit credentials |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4720 | User account created |
| 4726 | User account deleted |

---

## Getting Help

If you encounter issues:

1. Check this guide's Troubleshooting section
2. Review TECHNICAL.md for implementation details
3. Verify input file formats match specifications
4. Check evidence file integrity (hashes)
5. Review error messages carefully

---

**Document Version**: 1.0  
**Last Updated**: February 2026  
**For**: Digital Forensics Investigators
