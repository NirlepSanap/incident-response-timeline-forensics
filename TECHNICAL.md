# Technical Documentation
## Digital Incident Response and Timeline Reconstruction System

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Algorithm Details](#algorithm-details)
5. [API Reference](#api-reference)
6. [File Formats](#file-formats)
7. [Performance Optimization](#performance-optimization)

---

## System Architecture

### Component Overview

```
incident_response_system/
├── incident_response_system.py    # Core system implementation
├── generate_sample_data.py        # Sample data generator
├── demo.py                        # Demonstration script
├── README.md                      # User documentation
├── TECHNICAL.md                   # This file
├── logs/                          # Evidence input directory
│   ├── windows_events.json
│   ├── network_traffic.json
│   └── usb_activity.json
└── output/                        # Analysis results
    ├── timeline_visualization.html
    ├── forensic_report.txt
    └── timeline_export.json
```

### Class Hierarchy

```
ForensicEvent
    ├── Properties: timestamp, event_type, source, severity, description, details
    ├── Methods: to_dict()
    └── Attributes: attack_stage, ioc_tags

EvidenceIntegrity
    ├── calculate_hash(filepath, algorithm)
    └── verify_chain_of_custody(evidence_files)

LogParser
    ├── parse_windows_event_log(log_data)
    ├── parse_network_log(log_data)
    └── parse_usb_log(log_data)

AttackStageClassifier
    ├── classify_event(event)
    └── classify_all_events(events)

TimelineReconstructor
    ├── ingest_logs(windows_logs, network_logs, usb_logs)
    ├── correlate_events(time_window_seconds)
    ├── reconstruct_timeline()
    └── get_attack_summary()

VisualizationEngine
    └── generate_html_timeline(events, output_path)

ForensicReportGenerator
    └── generate_report(case_details, timeline, evidence_manifest, output_path)

IncidentResponseSystem
    ├── add_evidence_file(filepath)
    ├── ingest_forensic_data(windows_logs, network_logs, usb_logs)
    └── analyze_and_report(output_dir)
```

---

## Core Components

### 1. ForensicEvent Class

**Purpose**: Unified representation of forensic events from all sources

**Data Structure**:
```python
{
    'timestamp': datetime,           # Event occurrence time
    'event_type': str,               # Event classification
    'source': str,                   # Log source (Windows/Network/USB)
    'severity': str,                 # Critical/High/Warning/Information
    'description': str,              # Human-readable description
    'details': dict,                 # Source-specific metadata
    'attack_stage': str,             # MITRE ATT&CK stage
    'ioc_tags': list[str]           # Indicators of Compromise
}
```

**Key Methods**:
- `to_dict()`: Serializes event for JSON export

### 2. LogParser Class

**Purpose**: Normalizes heterogeneous log formats into ForensicEvent objects

#### Windows Event Log Parser

**Logic**:
```
FOR each log entry:
    1. Extract timestamp (ISO 8601 format)
    2. Parse Event ID
    3. Map Event ID to attack indicator:
       - 4624 → authentication
       - 4672 → privilege_escalation
       - 4688 → process_execution
       - 4698 → persistence
    4. Create ForensicEvent with normalized fields
```

**Event ID Mapping**:
| Event ID | Description | IOC Tag | Severity |
|----------|-------------|---------|----------|
| 4624 | Successful Logon | authentication | Information |
| 4672 | Special Privileges | privilege_escalation | Warning |
| 4688 | Process Creation | process_execution | Information |
| 4698 | Scheduled Task | persistence | Warning |
| 4634 | Account Logoff | - | Information |

#### Network Traffic Parser

**Logic**:
```
FOR each network flow:
    1. Extract source/destination IPs and ports
    2. Classify traffic direction (inbound/outbound)
    3. Detect suspicious patterns:
       - Remote access ports (22, 23, 3389)
       - Large data transfers (>1MB)
       - External communications (non-RFC1918)
    4. Assign severity based on risk
```

**Suspicious Port Detection**:
- **Remote Access**: 22 (SSH), 23 (Telnet), 3389 (RDP) → Warning
- **Data Exfiltration**: HTTPS (443) with >1MB → Critical
- **Blocked Traffic**: Any blocked connection → Warning

**IP Classification**:
```python
def is_internal(ip):
    return ip.startswith(('10.', '172.16.', '192.168.'))

if not is_internal(dst_ip):
    ioc_tags.append('external_communication')
```

#### USB Activity Parser

**Logic**:
```
FOR each USB event:
    1. Parse device metadata (VID, PID, serial)
    2. Classify action type:
       - connected → potential_exfiltration
       - data_transfer → data_exfiltration (Critical)
       - disconnected → cleanup
    3. Always mark as suspicious (removable media risk)
```

### 3. AttackStageClassifier

**Purpose**: Maps events to MITRE ATT&CK framework stages

**Classification Algorithm**:
```python
ATTACK_STAGES = {
    'Initial Access': ['remote_access', 'authentication', 'external_communication'],
    'Execution': ['process_execution', 'script_execution'],
    'Persistence': ['persistence', 'scheduled_task'],
    'Privilege Escalation': ['privilege_escalation', 'admin_access'],
    'Lateral Movement': ['remote_access', 'credential_use'],
    'Collection': ['file_access', 'clipboard_access'],
    'Exfiltration': ['data_exfiltration', 'removable_media', 'external_communication']
}

FOR each event:
    FOR each stage, indicators in ATTACK_STAGES:
        IF any IOC tag matches indicators:
            event.attack_stage = stage
            BREAK
```

**Stage Priority**: First match wins (order matters)

### 4. TimelineReconstructor

**Purpose**: Correlates and reconstructs chronological event timeline

#### Event Ingestion
```python
def ingest_logs(windows_logs, network_logs, usb_logs):
    events = []
    events.extend(parse_windows_logs(windows_logs))
    events.extend(parse_network_logs(network_logs))
    events.extend(parse_usb_logs(usb_logs))
    return events
```

#### Event Correlation Algorithm
```
INPUT: List of events, time_window (seconds)
OUTPUT: List of event clusters

SORT events by timestamp
SET current_cluster = []

FOR each event in sorted_events:
    IF current_cluster is empty:
        ADD event to current_cluster
    ELSE:
        time_diff = event.timestamp - last_event.timestamp
        IF time_diff <= time_window:
            ADD event to current_cluster
        ELSE:
            SAVE current_cluster
            START new cluster with event

RETURN all clusters
```

**Time Complexity**: O(n log n) for sorting + O(n) for clustering = **O(n log n)**

#### Timeline Reconstruction
```
ALGORITHM: reconstruct_timeline()
    1. Sort all events by timestamp
    2. Classify each event into attack stage
    3. Return sorted, classified timeline

Time Complexity: O(n log n)
Space Complexity: O(n)
```

### 5. EvidenceIntegrity

**Purpose**: Cryptographic verification for chain of custody

**Hash Calculation**:
```python
def calculate_hash(filepath, algorithm='sha256'):
    hash_obj = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):  # 8KB chunks
            hash_obj.update(chunk)
    return hash_obj.hexdigest()
```

**Chain of Custody Manifest**:
```json
{
    "filepath": {
        "sha256": "66b3dfec284bfe03c19167f521da0a9c...",
        "md5": "e4b9380caf77199c71d7c2a6dc9a76e7",
        "timestamp": "2026-02-09T10:45:29.877143"
    }
}
```

**Why Two Hashes?**
- **SHA-256**: Cryptographically secure, collision-resistant
- **MD5**: Widely supported, faster, good for comparison

---

## Data Flow

### Complete Analysis Pipeline

```
┌─────────────────┐
│  Evidence Files │
│  (.json format) │
└────────┬────────┘
         │
         ▼
┌────────────────────────────┐
│  1. Evidence Registration  │
│  - add_evidence_file()     │
│  - Calculate SHA-256, MD5  │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│  2. Log Parsing            │
│  - Parse Windows Events    │
│  - Parse Network Logs      │
│  - Parse USB Activity      │
│  → Create ForensicEvents   │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│  3. Event Normalization    │
│  - Standardize timestamps  │
│  - Extract metadata        │
│  - Tag IOCs                │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│  4. Timeline Reconstruction│
│  - Sort chronologically    │
│  - Correlate events        │
│  - Classify attack stages  │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│  5. Analysis & Summary     │
│  - Calculate statistics    │
│  - Identify patterns       │
│  - Generate findings       │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│  6. Output Generation      │
│  ├─ HTML Visualization     │
│  ├─ Forensic Report        │
│  └─ JSON Export            │
└────────────────────────────┘
```

### Event Processing Flow

```
Raw Log Entry
    ↓
Parse & Extract Fields
    ↓
Create ForensicEvent
    ↓
Tag IOCs (pattern matching)
    ↓
Classify Attack Stage
    ↓
Add to Timeline
    ↓
Generate Outputs
```

---

## Algorithm Details

### 1. Event Correlation Algorithm

**Problem**: Group related events occurring within a time window

**Approach**: Sliding window clustering

```python
def correlate_events(events, time_window=60):
    """
    Time Complexity: O(n log n) - dominated by sorting
    Space Complexity: O(n) - stores all events
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    clusters = []
    current_cluster = []
    
    for event in sorted_events:
        if not current_cluster:
            current_cluster = [event]
        else:
            time_diff = (event.timestamp - current_cluster[-1].timestamp).total_seconds()
            if time_diff <= time_window:
                current_cluster.append(event)
            else:
                clusters.append(current_cluster)
                current_cluster = [event]
    
    if current_cluster:
        clusters.append(current_cluster)
    
    return clusters
```

**Parameters**:
- `time_window`: Seconds between events to consider them related (default: 60)

**Example**:
```
Events: [E1(10:00), E2(10:01), E3(10:05), E4(10:06)]
Window: 60 seconds

Clusters: [[E1, E2, E3, E4]]  (all within 60s)

Events: [E1(10:00), E2(10:01), E3(11:00), E4(11:01)]
Window: 60 seconds

Clusters: [[E1, E2], [E3, E4]]  (gap > 60s)
```

### 2. Attack Stage Classification

**Problem**: Map events to MITRE ATT&CK stages

**Approach**: Rule-based pattern matching

```python
def classify_event(event):
    """
    Time Complexity: O(k*m) where k=stages, m=indicators per stage
    Space Complexity: O(1)
    """
    for stage, indicators in ATTACK_STAGES.items():
        if any(ioc in event.ioc_tags for ioc in indicators):
            return stage
    return 'Unknown'
```

**Optimization**: First match wins (early termination)

### 3. IOC Detection

**Pattern Matching Rules**:

```python
# Network-based IOCs
if dst_port in [22, 23, 3389]:  # O(1) set lookup
    ioc_tags.append('remote_access')

if bytes > 1_000_000 and dst_port in [80, 443]:
    ioc_tags.append('data_exfiltration')

if not is_internal_ip(dst_ip):  # O(1) string prefix check
    ioc_tags.append('external_communication')
```

### 4. Hash Calculation

**Algorithm**: Streaming hash for memory efficiency

```python
def calculate_hash(filepath, algorithm='sha256'):
    """
    Time Complexity: O(n) where n=file size
    Space Complexity: O(1) - constant buffer size
    """
    CHUNK_SIZE = 8192  # 8KB chunks
    hash_obj = hashlib.new(algorithm)
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()
```

**Why 8KB chunks?**
- Balances I/O efficiency and memory usage
- Typical filesystem block size
- Optimal for most modern systems

---

## API Reference

### IncidentResponseSystem Class

#### Constructor
```python
IncidentResponseSystem(case_id: str, case_details: Dict[str, Any])
```

**Parameters**:
- `case_id`: Unique identifier for the case
- `case_details`: Dictionary containing:
  - `incident_type`: Type of incident
  - `organization`: Organization name
  - `investigator`: Investigator name
  - `executive_summary`: Case overview
  - `conclusions`: Findings and recommendations

#### Methods

##### add_evidence_file()
```python
def add_evidence_file(filepath: str) -> None
```
Registers an evidence file for integrity verification.

**Parameters**:
- `filepath`: Path to evidence file

**Example**:
```python
system.add_evidence_file('./logs/windows_events.json')
```

##### ingest_forensic_data()
```python
def ingest_forensic_data(
    windows_logs: List[Dict] = None,
    network_logs: List[Dict] = None,
    usb_logs: List[Dict] = None
) -> None
```

**Parameters**:
- `windows_logs`: List of Windows Event Log entries
- `network_logs`: List of network traffic records
- `usb_logs`: List of USB activity records

**Example**:
```python
system.ingest_forensic_data(
    windows_logs=json.load(open('windows.json')),
    network_logs=json.load(open('network.json')),
    usb_logs=json.load(open('usb.json'))
)
```

##### analyze_and_report()
```python
def analyze_and_report(output_dir: str = './output') -> Dict[str, Any]
```

**Parameters**:
- `output_dir`: Directory for output files

**Returns**:
```python
{
    'timeline': List[ForensicEvent],
    'summary': Dict[str, Any],
    'evidence_manifest': Dict[str, Dict],
    'html_path': str,
    'report_path': str,
    'json_path': str
}
```

**Example**:
```python
results = system.analyze_and_report('./output')
print(f"Found {len(results['timeline'])} events")
```

---

## File Formats

### Input Format Specifications

#### Windows Event Log JSON
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

**Required Fields**: `timestamp`, `event_id`  
**Optional Fields**: All others  
**Timestamp Format**: ISO 8601 (YYYY-MM-DDTHH:MM:SS)

#### Network Traffic JSON
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

**Required Fields**: `timestamp`, `src_ip`, `dst_ip`, `dst_port`  
**Optional Fields**: `src_port`, `protocol`, `bytes`, `action`, `severity`

#### USB Activity JSON
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

**Required Fields**: `timestamp`, `device_id`, `action`  
**Optional Fields**: All others  
**Valid Actions**: `connected`, `disconnected`, `data_transfer`

### Output Format Specifications

#### Timeline Export JSON
```json
{
  "case_id": "IR-2026-001",
  "case_details": { ... },
  "summary": {
    "total_events": 76,
    "time_range": { ... },
    "severity_breakdown": { ... },
    "attack_stages": { ... }
  },
  "evidence_manifest": { ... },
  "timeline": [
    {
      "timestamp": "2026-02-09T08:45:29",
      "event_type": "4624",
      "source": "Windows Event Log",
      "severity": "Information",
      "description": "...",
      "details": { ... },
      "attack_stage": "Initial Access",
      "ioc_tags": ["authentication"]
    }
  ]
}
```

---

## Performance Optimization

### Memory Management

**Event Storage**: O(n) where n = number of events
- Average event size: ~500 bytes
- 10,000 events ≈ 5MB RAM

**Optimization Strategy**:
```python
# Use generators for large datasets
def process_large_log(filepath):
    with open(filepath) as f:
        for line in f:
            event = parse_line(line)
            yield event

# Process in chunks
for chunk in chunks(large_dataset, chunk_size=1000):
    process_chunk(chunk)
```

### Hash Calculation Optimization

**Current Implementation**:
- Chunk size: 8KB
- Performance: ~50MB/s for SHA-256

**Potential Improvements**:
```python
# Parallel hashing for multiple files
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(calculate_hash, f) for f in files]
    hashes = [f.result() for f in futures]
```

### Timeline Reconstruction Performance

**Current Complexity**:
- Sorting: O(n log n)
- Classification: O(n * k) where k = average IOC tags
- Total: O(n log n)

**Scalability**:
| Events | Time (estimate) |
|--------|-----------------|
| 1,000 | <0.1s |
| 10,000 | ~0.5s |
| 100,000 | ~5s |
| 1,000,000 | ~50s |

**Optimization for Large Datasets**:
```python
# Use numpy for faster operations
import numpy as np

timestamps = np.array([e.timestamp for e in events])
sorted_indices = np.argsort(timestamps)
sorted_events = [events[i] for i in sorted_indices]
```

### HTML Generation Optimization

**Current Approach**: Template-based generation
**File Size**: ~50KB for 100 events

**Optimization for Large Timelines**:
```python
# Lazy loading with pagination
events_per_page = 100
total_pages = len(events) // events_per_page

# Generate separate JSON files
for page in range(total_pages):
    start = page * events_per_page
    end = start + events_per_page
    save_json(f'events_page_{page}.json', events[start:end])
```

---

## Security Considerations

### Input Validation

**Required Checks**:
```python
def validate_timestamp(ts_string):
    try:
        datetime.fromisoformat(ts_string)
        return True
    except ValueError:
        return False

def validate_ip(ip_string):
    import ipaddress
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False
```

### Evidence Integrity

**Best Practices**:
1. Calculate hashes immediately upon evidence collection
2. Store hashes separately from evidence
3. Verify hashes before analysis
4. Re-verify after analysis
5. Document any discrepancies

### Data Sanitization

**For Reports**:
```python
def sanitize_text(text):
    # Remove potential HTML/script injection
    import html
    return html.escape(text)

# In HTML generation
description = sanitize_text(event.description)
```

---

## Testing Recommendations

### Unit Tests

```python
def test_event_correlation():
    events = [
        create_event(timestamp='2026-01-01T10:00:00'),
        create_event(timestamp='2026-01-01T10:00:30'),
        create_event(timestamp='2026-01-01T11:00:00')
    ]
    clusters = correlate_events(events, time_window=60)
    assert len(clusters) == 2
    assert len(clusters[0]) == 2
    assert len(clusters[1]) == 1
```

### Integration Tests

```python
def test_full_analysis_pipeline():
    system = IncidentResponseSystem('TEST-001', test_case_details)
    system.ingest_forensic_data(
        windows_logs=load_test_data('windows.json'),
        network_logs=load_test_data('network.json')
    )
    results = system.analyze_and_report('./test_output')
    
    assert len(results['timeline']) > 0
    assert os.path.exists(results['html_path'])
    assert os.path.exists(results['report_path'])
```

### Performance Tests

```python
def test_scalability():
    import time
    
    for size in [100, 1000, 10000]:
        events = generate_random_events(size)
        start = time.time()
        timeline = reconstruct_timeline(events)
        duration = time.time() - start
        
        print(f"{size} events: {duration:.3f}s")
        assert duration < size * 0.001  # <1ms per event
```

---

## Troubleshooting

### Common Issues

1. **Timestamp Parsing Errors**
   - Ensure ISO 8601 format
   - Check timezone handling

2. **Missing IOC Tags**
   - Verify pattern matching rules
   - Check event details extraction

3. **Memory Issues with Large Datasets**
   - Use chunked processing
   - Implement streaming analysis

4. **Hash Verification Failures**
   - Ensure file wasn't modified
   - Check file permissions
   - Verify hash algorithm match

---

**Document Version**: 1.0  
**Last Updated**: February 2026  
**Maintainer**: Digital Forensics Team
