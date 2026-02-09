# Digital Incident Response and Timeline Reconstruction System

## Overview

A comprehensive Digital Forensic and Incident Response (DFIR) system that automates the analysis of cyber incidents by correlating logs from multiple forensic sources. The system reconstructs chronological timelines, classifies attack stages, and generates professional forensic reports.

## Features

### Core Capabilities

- **Multi-Source Log Ingestion**: Processes Windows Event Logs, network traffic (PCAP/firewall), and USB device activity
- **Event Normalization**: Standardizes events from different sources into a unified format
- **Timeline Reconstruction**: Correlates events chronologically to reveal attack progression
- **Attack Stage Classification**: Maps events to MITRE ATT&CK framework stages
- **Evidence Integrity**: Cryptographic hash verification (SHA-256, MD5) for chain of custody
- **Interactive Visualization**: HTML-based graphical timeline with filtering capabilities
- **Forensic Reporting**: Professional incident reports with detailed analysis

### Attack Stages Detected

Based on MITRE ATT&CK framework:

- **Initial Access**: Remote connections, authentication events
- **Execution**: Process creation, script execution
- **Persistence**: Scheduled tasks, registry modifications
- **Privilege Escalation**: Admin access, special privileges
- **Lateral Movement**: Credential usage, remote access
- **Collection**: File access, clipboard activity
- **Exfiltration**: Network data transfer, removable media usage

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Evidence Sources                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Windows  │  │ Network  │  │   USB    │                  │
│  │  Events  │  │ Traffic  │  │ Activity │                  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                  │
└───────┼─────────────┼─────────────┼────────────────────────┘
        │             │             │
        └─────────────┼─────────────┘
                      │
        ┌─────────────▼────────────────┐
        │      Log Parser              │
        │  (Normalization Engine)      │
        └─────────────┬────────────────┘
                      │
        ┌─────────────▼────────────────┐
        │   Timeline Reconstructor     │
        │  • Event Correlation         │
        │  • Attack Classification     │
        └─────────────┬────────────────┘
                      │
        ┌─────────────▼────────────────┐
        │   Evidence Integrity         │
        │  • SHA-256 Hashing           │
        │  • Chain of Custody          │
        └─────────────┬────────────────┘
                      │
        ┌─────────────▼────────────────┐
        │   Output Generation          │
        │  ┌────────────────────────┐  │
        │  │ HTML Visualization     │  │
        │  ├────────────────────────┤  │
        │  │ Forensic Report        │  │
        │  ├────────────────────────┤  │
        │  │ JSON Export            │  │
        │  └────────────────────────┘  │
        └──────────────────────────────┘
```

## Installation and Usage

### Quick Start

```bash
# Run the demonstration
python demo.py

# View help
python demo.py --help
```

### Custom Analysis

```python
from incident_response_system import IncidentResponseSystem
import json

# 1. Initialize the system
case_details = {
    'case_id': 'IR-2026-001',
    'incident_type': 'Data Breach Investigation',
    'organization': 'Your Organization',
    'investigator': 'Your Name'
}

system = IncidentResponseSystem('IR-2026-001', case_details)

# 2. Register evidence files
system.add_evidence_file('./evidence/windows_events.json')
system.add_evidence_file('./evidence/network_logs.json')
system.add_evidence_file('./evidence/usb_logs.json')

# 3. Load log data
with open('./evidence/windows_events.json') as f:
    windows_logs = json.load(f)

with open('./evidence/network_logs.json') as f:
    network_logs = json.load(f)

with open('./evidence/usb_logs.json') as f:
    usb_logs = json.load(f)

# 4. Ingest forensic data
system.ingest_forensic_data(
    windows_logs=windows_logs,
    network_logs=network_logs,
    usb_logs=usb_logs
)

# 5. Analyze and generate reports
results = system.analyze_and_report('./output')

print(f"Analysis complete. Timeline has {len(results['timeline'])} events.")
```

## Log Format Specifications

### Windows Event Log Format

```json
{
  "timestamp": "2026-02-09T10:30:45",
  "event_id": "4624",
  "level": "Information",
  "channel": "Security",
  "message": "An account was successfully logged on",
  "computer": "WORKSTATION-01",
  "user": "JohnDoe",
  "process_id": 1234
}
```

**Key Event IDs:**
- `4624`: Successful logon
- `4672`: Special privileges assigned (privilege escalation)
- `4688`: Process creation
- `4698`: Scheduled task created (persistence)
- `4634`: Account logoff

### Network Traffic Log Format

```json
{
  "timestamp": "2026-02-09T10:31:00",
  "src_ip": "192.168.1.10",
  "dst_ip": "203.0.113.45",
  "src_port": 52341,
  "dst_port": 443,
  "protocol": "TCP",
  "bytes": 5242880,
  "action": "allowed",
  "severity": "Critical"
}
```

### USB Activity Log Format

```json
{
  "timestamp": "2026-02-09T10:32:00",
  "device_id": "USB\\VID_0951&PID_1666",
  "device_name": "Kingston DataTraveler 3.0",
  "serial_number": "AA0123456789",
  "action": "connected",
  "user": "JohnDoe",
  "volume_name": "USBDRIVE1",
  "severity": "High"
}
```

**Actions:**
- `connected`: Device plugged in
- `disconnected`: Device removed
- `data_transfer`: Data copied to/from device

## Output Files

### 1. Interactive Timeline Visualization
**File**: `output/timeline_visualization.html`

Features:
- Chronological event display with color coding
- Severity-based filtering (Critical, High, Warning, Information)
- Attack stage tags
- Detailed event information
- Real-time statistics

### 2. Forensic Report
**File**: `output/forensic_report.txt`

Contents:
- Case information and metadata
- Executive summary
- Evidence sources with cryptographic hashes
- Attack stage analysis
- Severity distribution
- Critical events timeline
- Key findings and recommendations
- Investigator certification

### 3. JSON Export
**File**: `output/timeline_export.json`

Structured data including:
- Complete event timeline
- Evidence manifest
- Attack summary statistics
- All case details

## DFIR Principles Implemented

### 1. Chain of Custody
- SHA-256 and MD5 hashing of all evidence files
- Timestamp recording for evidence collection
- Evidence manifest generation
- Tamper detection through hash verification

### 2. Event Correlation
- Time-window based event clustering
- Cross-source event correlation
- Pattern detection across log types
- Attack sequence reconstruction

### 3. Timeline Analysis
- Chronological event ordering
- Temporal correlation
- Attack progression mapping
- Duration and time-span analysis

### 4. Indicator of Compromise (IOC) Detection

Automatically identifies:
- Authentication anomalies
- Privilege escalation attempts
- Remote access connections
- External communications
- Data exfiltration patterns
- Removable media usage
- Persistence mechanisms

### 5. Professional Reporting
- Standardized report format
- Executive summary for management
- Technical details for analysts
- Evidence preservation documentation
- Actionable recommendations

## Use Cases

### 1. Data Breach Investigation
Analyze suspected data exfiltration incidents by correlating network traffic with USB activity and system events.

### 2. Insider Threat Detection
Identify unauthorized access, privilege abuse, and data theft by internal actors.

### 3. Malware Incident Response
Reconstruct attack timelines showing initial infection, lateral movement, and payload execution.

### 4. Compliance Auditing
Generate forensic reports for compliance requirements (PCI-DSS, HIPAA, GDPR).

### 5. Security Training
Demonstrate attack techniques and forensic analysis methods in educational settings.

## Attack Scenario Example

The demonstration includes a realistic attack scenario:

1. **Initial Access** (T0): External RDP connection from 198.51.100.89
2. **Authentication** (T+5s): Successful logon as "attacker@external.com"
3. **Privilege Escalation** (T+5m): Special privileges assigned
4. **Persistence** (T+7m): Scheduled task created
5. **Data Collection** (T+17m): Large data transfers via HTTPS
6. **Exfiltration** (T+32m): USB device connected
7. **Data Transfer** (T+37m): Files copied to removable media
8. **Cover Tracks** (T+49m): Account logoff

## Performance Considerations

- **Event Processing**: ~1000 events/second
- **Memory Usage**: Scales linearly with event count (~1MB per 10,000 events)
- **Hash Calculation**: Depends on file size (SHA-256 ~50MB/s)
- **Timeline Generation**: O(n log n) complexity for sorting

## Best Practices

### Evidence Collection
1. Create forensic copies of original logs
2. Calculate hashes before and after transfer
3. Document collection time and method
4. Store evidence in tamper-proof format

### Analysis Workflow
1. Start with attack summary for context
2. Review critical events first
3. Examine temporal patterns
4. Correlate across log sources
5. Verify findings with original evidence

### Reporting
1. Include executive summary for stakeholders
2. Provide technical details for investigators
3. Document all evidence sources
4. Make actionable recommendations
5. Maintain chain of custody records

## Limitations

- Does not decrypt encrypted network traffic
- Requires standardized log formats
- Time correlation assumes synchronized clocks
- Cannot detect all sophisticated evasion techniques
- Manual verification still recommended

## Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] Real-time log streaming support
- [ ] PCAP file parsing integration
- [ ] Memory dump analysis
- [ ] Registry hive parsing
- [ ] Automated IOC extraction
- [ ] Threat intelligence integration
- [ ] Multi-case comparison
- [ ] Cloud log source support (AWS, Azure, GCP)
- [ ] Mobile device forensics

## Security Considerations

### Data Handling
- Log files may contain sensitive information
- Implement access controls on forensic data
- Encrypt evidence at rest and in transit
- Follow data retention policies

### Privacy
- Redact personally identifiable information (PII) when necessary
- Comply with local privacy regulations
- Document data handling procedures

## Contributing

This is a demonstration system. For production use:
- Add comprehensive input validation
- Implement proper error handling
- Add logging and audit trails
- Include unit and integration tests
- Follow secure coding practices

## License

Educational and demonstration purposes.

## References

- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- MITRE ATT&CK Framework: https://attack.mitre.org/
- SANS Digital Forensics and Incident Response: https://www.sans.org/dfir/
- RFC 3227: Guidelines for Evidence Collection and Archiving

## Support

For questions or issues:
1. Review the demonstration output
2. Check log format specifications
3. Verify evidence file integrity
4. Consult DFIR best practices documentation

---

**Version**: 1.0  
**Date**: February 2026  
**Author**: Nirlep Sanap

