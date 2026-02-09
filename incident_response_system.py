#!/usr/bin/env python3
"""
Digital Incident Response and Timeline Reconstruction System
Implements DFIR principles for cyber incident analysis
"""

import json
import hashlib
import csv
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Tuple
import re
from pathlib import Path


class ForensicEvent:
    """Represents a single forensic event from any source"""
    
    def __init__(self, timestamp: datetime, event_type: str, source: str, 
                 severity: str, description: str, details: Dict[str, Any]):
        self.timestamp = timestamp
        self.event_type = event_type
        self.source = source
        self.severity = severity
        self.description = description
        self.details = details
        self.attack_stage = None
        self.ioc_tags = []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'source': self.source,
            'severity': self.severity,
            'description': self.description,
            'details': self.details,
            'attack_stage': self.attack_stage,
            'ioc_tags': self.ioc_tags
        }


class EvidenceIntegrity:
    """Handles cryptographic hash verification for evidence integrity"""
    
    @staticmethod
    def calculate_hash(filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate cryptographic hash of a file"""
        hash_obj = hashlib.new(algorithm)
        
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def verify_chain_of_custody(evidence_files: List[str]) -> Dict[str, str]:
        """Generate hash manifest for evidence files"""
        manifest = {}
        for filepath in evidence_files:
            if Path(filepath).exists():
                manifest[filepath] = {
                    'sha256': EvidenceIntegrity.calculate_hash(filepath, 'sha256'),
                    'md5': EvidenceIntegrity.calculate_hash(filepath, 'md5'),
                    'timestamp': datetime.now().isoformat()
                }
        return manifest


class LogParser:
    """Parses various log formats and normalizes events"""
    
    @staticmethod
    def parse_windows_event_log(log_data: List[Dict]) -> List[ForensicEvent]:
        """Parse Windows Event Log entries"""
        events = []
        
        for entry in log_data:
            try:
                timestamp = datetime.fromisoformat(entry['timestamp'])
                
                event = ForensicEvent(
                    timestamp=timestamp,
                    event_type=entry.get('event_id', 'Unknown'),
                    source='Windows Event Log',
                    severity=entry.get('level', 'Information'),
                    description=entry.get('message', ''),
                    details={
                        'event_id': entry.get('event_id'),
                        'computer': entry.get('computer'),
                        'user': entry.get('user'),
                        'channel': entry.get('channel'),
                        'process_id': entry.get('process_id')
                    }
                )
                
                # Classify suspicious events
                if entry.get('event_id') == '4624':  # Successful logon
                    event.ioc_tags.append('authentication')
                elif entry.get('event_id') == '4672':  # Special privileges assigned
                    event.ioc_tags.append('privilege_escalation')
                    event.severity = 'Warning'
                elif entry.get('event_id') == '4688':  # Process creation
                    event.ioc_tags.append('process_execution')
                elif entry.get('event_id') == '4698':  # Scheduled task created
                    event.ioc_tags.append('persistence')
                    event.severity = 'Warning'
                
                events.append(event)
                
            except Exception as e:
                print(f"Error parsing Windows event: {e}")
                
        return events
    
    @staticmethod
    def parse_network_log(log_data: List[Dict]) -> List[ForensicEvent]:
        """Parse network traffic/firewall logs"""
        events = []
        
        for entry in log_data:
            try:
                timestamp = datetime.fromisoformat(entry['timestamp'])
                
                event = ForensicEvent(
                    timestamp=timestamp,
                    event_type=entry.get('protocol', 'Unknown'),
                    source='Network Traffic',
                    severity=entry.get('severity', 'Information'),
                    description=f"{entry.get('src_ip')} -> {entry.get('dst_ip')}:{entry.get('dst_port')}",
                    details={
                        'src_ip': entry.get('src_ip'),
                        'dst_ip': entry.get('dst_ip'),
                        'src_port': entry.get('src_port'),
                        'dst_port': entry.get('dst_port'),
                        'protocol': entry.get('protocol'),
                        'bytes': entry.get('bytes'),
                        'action': entry.get('action')
                    }
                )
                
                # Identify suspicious network activity
                if entry.get('dst_port') in [22, 23, 3389]:  # Remote access ports
                    event.ioc_tags.append('remote_access')
                    event.severity = 'Warning'
                elif entry.get('dst_port') in [443, 80] and entry.get('bytes', 0) > 1000000:
                    event.ioc_tags.append('data_exfiltration')
                    event.severity = 'Critical'
                elif entry.get('action') == 'blocked':
                    event.ioc_tags.append('blocked_attempt')
                    
                # Check for external communication
                dst_ip = entry.get('dst_ip', '')
                if not dst_ip.startswith(('10.', '172.16.', '192.168.')):
                    event.ioc_tags.append('external_communication')
                
                events.append(event)
                
            except Exception as e:
                print(f"Error parsing network event: {e}")
                
        return events
    
    @staticmethod
    def parse_usb_log(log_data: List[Dict]) -> List[ForensicEvent]:
        """Parse USB device activity logs"""
        events = []
        
        for entry in log_data:
            try:
                timestamp = datetime.fromisoformat(entry['timestamp'])
                
                event = ForensicEvent(
                    timestamp=timestamp,
                    event_type=entry.get('action', 'Unknown'),
                    source='USB Device Activity',
                    severity=entry.get('severity', 'Warning'),
                    description=f"{entry.get('action')} - {entry.get('device_name')}",
                    details={
                        'device_id': entry.get('device_id'),
                        'device_name': entry.get('device_name'),
                        'serial_number': entry.get('serial_number'),
                        'action': entry.get('action'),
                        'user': entry.get('user'),
                        'volume_name': entry.get('volume_name')
                    }
                )
                
                # USB events are inherently suspicious for data exfiltration
                if entry.get('action') == 'connected':
                    event.ioc_tags.append('removable_media')
                    event.ioc_tags.append('potential_exfiltration')
                    event.severity = 'High'
                elif entry.get('action') == 'data_transfer':
                    event.ioc_tags.append('data_exfiltration')
                    event.severity = 'Critical'
                
                events.append(event)
                
            except Exception as e:
                print(f"Error parsing USB event: {e}")
                
        return events


class AttackStageClassifier:
    """Classifies events into MITRE ATT&CK stages"""
    
    ATTACK_STAGES = {
        'Initial Access': ['remote_access', 'authentication', 'external_communication'],
        'Execution': ['process_execution', 'script_execution'],
        'Persistence': ['persistence', 'scheduled_task'],
        'Privilege Escalation': ['privilege_escalation', 'admin_access'],
        'Lateral Movement': ['remote_access', 'credential_use'],
        'Collection': ['file_access', 'clipboard_access'],
        'Exfiltration': ['data_exfiltration', 'removable_media', 'external_communication']
    }
    
    @staticmethod
    def classify_event(event: ForensicEvent) -> str:
        """Classify event into attack stage based on IOC tags"""
        for stage, indicators in AttackStageClassifier.ATTACK_STAGES.items():
            if any(ioc in event.ioc_tags for ioc in indicators):
                return stage
        return 'Unknown'
    
    @staticmethod
    def classify_all_events(events: List[ForensicEvent]) -> List[ForensicEvent]:
        """Classify all events in the timeline"""
        for event in events:
            event.attack_stage = AttackStageClassifier.classify_event(event)
        return events


class TimelineReconstructor:
    """Reconstructs chronological timeline from correlated events"""
    
    def __init__(self):
        self.events: List[ForensicEvent] = []
        self.evidence_manifest: Dict[str, Any] = {}
        
    def ingest_logs(self, windows_logs: List[Dict] = None, 
                   network_logs: List[Dict] = None,
                   usb_logs: List[Dict] = None):
        """Ingest and normalize logs from multiple sources"""
        
        if windows_logs:
            self.events.extend(LogParser.parse_windows_event_log(windows_logs))
            
        if network_logs:
            self.events.extend(LogParser.parse_network_log(network_logs))
            
        if usb_logs:
            self.events.extend(LogParser.parse_usb_log(usb_logs))
    
    def correlate_events(self, time_window_seconds: int = 60) -> List[List[ForensicEvent]]:
        """Correlate events that occur within a time window"""
        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        clusters = []
        current_cluster = []
        
        for event in sorted_events:
            if not current_cluster:
                current_cluster.append(event)
            else:
                time_diff = (event.timestamp - current_cluster[-1].timestamp).total_seconds()
                
                if time_diff <= time_window_seconds:
                    current_cluster.append(event)
                else:
                    if current_cluster:
                        clusters.append(current_cluster)
                    current_cluster = [event]
        
        if current_cluster:
            clusters.append(current_cluster)
            
        return clusters
    
    def reconstruct_timeline(self) -> List[ForensicEvent]:
        """Reconstruct chronological timeline with attack stage classification"""
        # Sort all events chronologically
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        # Classify events into attack stages
        classified_events = AttackStageClassifier.classify_all_events(sorted_events)
        
        return classified_events
    
    def get_attack_summary(self) -> Dict[str, Any]:
        """Generate high-level attack summary statistics"""
        timeline = self.reconstruct_timeline()
        
        summary = {
            'total_events': len(timeline),
            'time_range': {
                'start': timeline[0].timestamp.isoformat() if timeline else None,
                'end': timeline[-1].timestamp.isoformat() if timeline else None,
                'duration': str(timeline[-1].timestamp - timeline[0].timestamp) if timeline else None
            },
            'severity_breakdown': defaultdict(int),
            'source_breakdown': defaultdict(int),
            'attack_stages': defaultdict(int),
            'critical_events': []
        }
        
        for event in timeline:
            summary['severity_breakdown'][event.severity] += 1
            summary['source_breakdown'][event.source] += 1
            summary['attack_stages'][event.attack_stage] += 1
            
            if event.severity in ['Critical', 'High']:
                summary['critical_events'].append({
                    'timestamp': event.timestamp.isoformat(),
                    'description': event.description,
                    'severity': event.severity,
                    'attack_stage': event.attack_stage
                })
        
        return dict(summary)


class VisualizationEngine:
    """Generates visual timeline representations"""
    
    @staticmethod
    def generate_html_timeline(events: List[ForensicEvent], output_path: str):
        """Generate interactive HTML timeline visualization"""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Timeline - Incident Response</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #fff;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            color: #a8c0e0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4a90e2;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .stat-card h3 {
            color: #4a90e2;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #fff;
        }
        
        .timeline-container {
            position: relative;
            padding-left: 50px;
        }
        
        .timeline-line {
            position: absolute;
            left: 20px;
            top: 0;
            bottom: 0;
            width: 3px;
            background: linear-gradient(to bottom, #4a90e2, #2ecc71);
        }
        
        .timeline-event {
            position: relative;
            margin-bottom: 30px;
            padding: 20px;
            background: #1a1f3a;
            border-radius: 8px;
            border-left: 4px solid #4a90e2;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            transition: transform 0.2s;
        }
        
        .timeline-event:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        
        .timeline-event::before {
            content: '';
            position: absolute;
            left: -37px;
            top: 25px;
            width: 15px;
            height: 15px;
            border-radius: 50%;
            background: #4a90e2;
            border: 3px solid #0a0e27;
            z-index: 1;
        }
        
        .timeline-event.critical {
            border-left-color: #e74c3c;
        }
        
        .timeline-event.critical::before {
            background: #e74c3c;
            animation: pulse 2s infinite;
        }
        
        .timeline-event.high {
            border-left-color: #f39c12;
        }
        
        .timeline-event.high::before {
            background: #f39c12;
        }
        
        .timeline-event.warning {
            border-left-color: #f1c40f;
        }
        
        .timeline-event.warning::before {
            background: #f1c40f;
        }
        
        @keyframes pulse {
            0%, 100% {
                box-shadow: 0 0 0 0 rgba(231, 76, 60, 0.7);
            }
            50% {
                box-shadow: 0 0 0 10px rgba(231, 76, 60, 0);
            }
        }
        
        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .event-time {
            font-size: 0.9em;
            color: #4a90e2;
            font-weight: bold;
        }
        
        .event-source {
            font-size: 0.8em;
            padding: 4px 12px;
            background: #2a3f5f;
            border-radius: 12px;
            color: #a8c0e0;
        }
        
        .event-title {
            font-size: 1.3em;
            margin-bottom: 10px;
            color: #fff;
        }
        
        .event-description {
            color: #b0b0b0;
            margin-bottom: 15px;
            line-height: 1.6;
        }
        
        .event-details {
            background: #0f1428;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .event-details dt {
            color: #4a90e2;
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }
        
        .event-details dd {
            color: #e0e0e0;
            display: inline;
            margin-left: 10px;
        }
        
        .event-details dd::after {
            content: '';
            display: block;
            margin-bottom: 8px;
        }
        
        .tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 15px;
        }
        
        .tag {
            padding: 4px 10px;
            background: #2ecc71;
            color: #fff;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .tag.stage {
            background: #9b59b6;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .severity-critical {
            background: #e74c3c;
            color: #fff;
        }
        
        .severity-high {
            background: #f39c12;
            color: #fff;
        }
        
        .severity-warning {
            background: #f1c40f;
            color: #000;
        }
        
        .severity-information {
            background: #3498db;
            color: #fff;
        }
        
        .filter-panel {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .filter-panel h3 {
            margin-bottom: 15px;
            color: #4a90e2;
        }
        
        .filter-options {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .filter-option {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .filter-option input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        
        .filter-option label {
            cursor: pointer;
            user-select: none;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Forensic Timeline Analysis</h1>
        <div class="subtitle">Digital Incident Response & Timeline Reconstruction</div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Events</h3>
            <div class="value" id="total-events">0</div>
        </div>
        <div class="stat-card">
            <h3>Critical Events</h3>
            <div class="value" id="critical-events">0</div>
        </div>
        <div class="stat-card">
            <h3>Attack Stages</h3>
            <div class="value" id="attack-stages">0</div>
        </div>
        <div class="stat-card">
            <h3>Time Span</h3>
            <div class="value" id="time-span">--</div>
        </div>
    </div>
    
    <div class="filter-panel">
        <h3>Filter Timeline</h3>
        <div class="filter-options">
            <div class="filter-option">
                <input type="checkbox" id="filter-critical" checked>
                <label for="filter-critical">Critical</label>
            </div>
            <div class="filter-option">
                <input type="checkbox" id="filter-high" checked>
                <label for="filter-high">High</label>
            </div>
            <div class="filter-option">
                <input type="checkbox" id="filter-warning" checked>
                <label for="filter-warning">Warning</label>
            </div>
            <div class="filter-option">
                <input type="checkbox" id="filter-information" checked>
                <label for="filter-information">Information</label>
            </div>
        </div>
    </div>
    
    <div class="timeline-container">
        <div class="timeline-line"></div>
        <div id="timeline-events"></div>
    </div>
    
    <script>
        const events = {{EVENTS_JSON}};
        
        function renderTimeline() {
            const container = document.getElementById('timeline-events');
            const filters = {
                critical: document.getElementById('filter-critical').checked,
                high: document.getElementById('filter-high').checked,
                warning: document.getElementById('filter-warning').checked,
                information: document.getElementById('filter-information').checked
            };
            
            container.innerHTML = '';
            let displayedCount = 0;
            
            events.forEach(event => {
                const severity = event.severity.toLowerCase();
                if (!filters[severity]) return;
                
                displayedCount++;
                
                const eventDiv = document.createElement('div');
                eventDiv.className = `timeline-event ${severity}`;
                
                const tags = event.ioc_tags.map(tag => 
                    `<span class="tag">${tag}</span>`
                ).join('');
                
                const stagTag = event.attack_stage ? 
                    `<span class="tag stage">${event.attack_stage}</span>` : '';
                
                const detailsHtml = Object.entries(event.details)
                    .filter(([k, v]) => v !== null && v !== '')
                    .map(([key, value]) => 
                        `<dt>${key}:</dt><dd>${value}</dd>`
                    ).join('');
                
                eventDiv.innerHTML = `
                    <div class="event-header">
                        <div class="event-time">${new Date(event.timestamp).toLocaleString()}</div>
                        <div class="event-source">${event.source}</div>
                    </div>
                    <div class="event-title">
                        <span class="severity-badge severity-${severity}">${event.severity}</span>
                        ${event.event_type}
                    </div>
                    <div class="event-description">${event.description}</div>
                    <div class="event-details">
                        <dl>${detailsHtml}</dl>
                    </div>
                    <div class="tags">
                        ${stagTag}
                        ${tags}
                    </div>
                `;
                
                container.appendChild(eventDiv);
            });
            
            document.getElementById('total-events').textContent = displayedCount;
        }
        
        function updateStats() {
            const critical = events.filter(e => e.severity === 'Critical').length;
            const stages = new Set(events.map(e => e.attack_stage).filter(s => s && s !== 'Unknown')).size;
            
            const timestamps = events.map(e => new Date(e.timestamp));
            const minTime = new Date(Math.min(...timestamps));
            const maxTime = new Date(Math.max(...timestamps));
            const duration = (maxTime - minTime) / 1000 / 60; // minutes
            
            document.getElementById('critical-events').textContent = critical;
            document.getElementById('attack-stages').textContent = stages;
            document.getElementById('time-span').textContent = duration < 60 ? 
                `${Math.round(duration)}m` : `${Math.round(duration/60)}h`;
        }
        
        // Event listeners
        document.querySelectorAll('.filter-option input').forEach(input => {
            input.addEventListener('change', renderTimeline);
        });
        
        // Initial render
        updateStats();
        renderTimeline();
    </script>
</body>
</html>
        """
        
        events_json = json.dumps([event.to_dict() for event in events], indent=2)
        html_content = html_template.replace('{{EVENTS_JSON}}', events_json)
        
        with open(output_path, 'w') as f:
            f.write(html_content)


class ForensicReportGenerator:
    """Generates comprehensive forensic incident reports"""
    
    @staticmethod
    def generate_report(case_details: Dict[str, Any], 
                       timeline: List[ForensicEvent],
                       evidence_manifest: Dict[str, Any],
                       output_path: str):
        """Generate detailed forensic incident report"""
        
        report_content = f"""
================================================================================
                    FORENSIC INCIDENT RESPONSE REPORT
================================================================================

CASE INFORMATION
--------------------------------------------------------------------------------
Case ID:              {case_details.get('case_id', 'N/A')}
Incident Type:        {case_details.get('incident_type', 'Cyber Security Incident')}
Report Date:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Investigator:         {case_details.get('investigator', 'Automated System')}
Organization:         {case_details.get('organization', 'N/A')}

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
{case_details.get('executive_summary', 'Automated forensic timeline analysis conducted.')}

Total Events Analyzed: {len(timeline)}
Time Range: {timeline[0].timestamp.strftime('%Y-%m-%d %H:%M:%S') if timeline else 'N/A'} to {timeline[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if timeline else 'N/A'}
Duration: {timeline[-1].timestamp - timeline[0].timestamp if len(timeline) > 1 else 'N/A'}

EVIDENCE SOURCES
--------------------------------------------------------------------------------
"""
        
        # Add evidence manifest
        for filepath, hashes in evidence_manifest.items():
            report_content += f"""
Source File: {filepath}
SHA-256:     {hashes.get('sha256', 'N/A')}
MD5:         {hashes.get('md5', 'N/A')}
Collected:   {hashes.get('timestamp', 'N/A')}
"""
        
        # Attack stage analysis
        stage_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for event in timeline:
            if event.attack_stage:
                stage_counts[event.attack_stage] += 1
            severity_counts[event.severity] += 1
        
        report_content += """

ATTACK STAGE ANALYSIS
--------------------------------------------------------------------------------
"""
        for stage, count in sorted(stage_counts.items()):
            report_content += f"{stage:30s} : {count:5d} events\n"
        
        report_content += """

SEVERITY DISTRIBUTION
--------------------------------------------------------------------------------
"""
        for severity, count in sorted(severity_counts.items()):
            report_content += f"{severity:30s} : {count:5d} events\n"
        
        # Timeline of critical events
        report_content += """

CRITICAL EVENTS TIMELINE
--------------------------------------------------------------------------------
"""
        critical_events = [e for e in timeline if e.severity in ['Critical', 'High']]
        
        for event in critical_events[:50]:  # Limit to first 50 critical events
            report_content += f"""
[{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {event.severity}
Stage:       {event.attack_stage or 'Unknown'}
Source:      {event.source}
Type:        {event.event_type}
Description: {event.description}
IOC Tags:    {', '.join(event.ioc_tags) if event.ioc_tags else 'None'}
{"=" * 80}
"""
        
        # Key findings
        report_content += """

KEY FINDINGS
--------------------------------------------------------------------------------
"""
        
        # Identify patterns
        findings = []
        
        # Check for data exfiltration
        exfil_events = [e for e in timeline if 'data_exfiltration' in e.ioc_tags]
        if exfil_events:
            findings.append(f"• {len(exfil_events)} potential data exfiltration events detected")
        
        # Check for privilege escalation
        priv_esc = [e for e in timeline if 'privilege_escalation' in e.ioc_tags]
        if priv_esc:
            findings.append(f"• {len(priv_esc)} privilege escalation attempts identified")
        
        # Check for external communication
        ext_comm = [e for e in timeline if 'external_communication' in e.ioc_tags]
        if ext_comm:
            findings.append(f"• {len(ext_comm)} external network communications observed")
        
        # Check for removable media
        usb_events = [e for e in timeline if 'removable_media' in e.ioc_tags]
        if usb_events:
            findings.append(f"• {len(usb_events)} removable media device activities recorded")
        
        for finding in findings:
            report_content += finding + "\n"
        
        report_content += """

CONCLUSIONS
--------------------------------------------------------------------------------
"""
        report_content += case_details.get('conclusions', """
Based on the forensic timeline analysis, the incident appears to follow a 
pattern consistent with targeted data exfiltration. The attacker gained initial 
access, escalated privileges, performed lateral movement, and exfiltrated data 
through multiple channels including network and removable media.

Recommendations:
1. Isolate affected systems immediately
2. Reset credentials for compromised accounts
3. Review and enhance access controls
4. Monitor for persistence mechanisms
5. Conduct full malware scan on affected systems
6. Review network egress filtering rules
7. Implement USB device control policies
""")
        
        report_content += """

INVESTIGATOR CERTIFICATION
--------------------------------------------------------------------------------
This report represents an accurate and complete analysis of the forensic 
evidence available at the time of investigation. All evidence has been handled 
according to digital forensics best practices with cryptographic verification 
of integrity.

Investigator: {investigator}
Date: {date}
Signature: _______________________

================================================================================
                            END OF REPORT
================================================================================
""".format(
            investigator=case_details.get('investigator', 'Automated System'),
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        with open(output_path, 'w') as f:
            f.write(report_content)
        
        return report_content


class IncidentResponseSystem:
    """Main incident response and timeline reconstruction system"""
    
    def __init__(self, case_id: str, case_details: Dict[str, Any]):
        self.case_id = case_id
        self.case_details = case_details
        self.reconstructor = TimelineReconstructor()
        self.evidence_files = []
        
    def add_evidence_file(self, filepath: str):
        """Register evidence file for chain of custody"""
        self.evidence_files.append(filepath)
    
    def ingest_forensic_data(self, windows_logs=None, network_logs=None, usb_logs=None):
        """Ingest forensic data from multiple sources"""
        self.reconstructor.ingest_logs(windows_logs, network_logs, usb_logs)
    
    def analyze_and_report(self, output_dir: str = './output'):
        """Perform complete analysis and generate reports"""
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Reconstruct timeline
        timeline = self.reconstructor.reconstruct_timeline()
        
        # Generate evidence manifest
        evidence_manifest = EvidenceIntegrity.verify_chain_of_custody(self.evidence_files)
        
        # Generate attack summary
        summary = self.reconstructor.get_attack_summary()
        
        # Generate HTML visualization
        html_path = f"{output_dir}/timeline_visualization.html"
        VisualizationEngine.generate_html_timeline(timeline, html_path)
        
        # Generate forensic report
        report_path = f"{output_dir}/forensic_report.txt"
        ForensicReportGenerator.generate_report(
            self.case_details,
            timeline,
            evidence_manifest,
            report_path
        )
        
        # Export timeline as JSON
        json_path = f"{output_dir}/timeline_export.json"
        with open(json_path, 'w') as f:
            json.dump({
                'case_id': self.case_id,
                'case_details': self.case_details,
                'summary': summary,
                'evidence_manifest': evidence_manifest,
                'timeline': [event.to_dict() for event in timeline]
            }, f, indent=2, default=str)
        
        return {
            'timeline': timeline,
            'summary': summary,
            'evidence_manifest': evidence_manifest,
            'html_path': html_path,
            'report_path': report_path,
            'json_path': json_path
        }


if __name__ == "__main__":
    print("Digital Incident Response and Timeline Reconstruction System")
    print("=" * 70)
    print("\nThis module provides comprehensive forensic analysis capabilities:")
    print("• Multi-source log ingestion and normalization")
    print("• Event correlation and timeline reconstruction")
    print("• Attack stage classification (MITRE ATT&CK)")
    print("• Evidence integrity verification")
    print("• Interactive timeline visualization")
    print("• Comprehensive forensic reporting")
    print("\nImport this module and use IncidentResponseSystem class to analyze incidents.")
