#!/usr/bin/env python3
"""
Incident Response System - Demonstration
Complete workflow for forensic timeline reconstruction
"""

import sys
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from incident_response_system import (
    IncidentResponseSystem,
    EvidenceIntegrity
)
from generate_sample_data import save_sample_data


def demonstrate_incident_response():
    """Complete demonstration of the incident response system"""
    
    print("=" * 80)
    print(" DIGITAL INCIDENT RESPONSE AND TIMELINE RECONSTRUCTION SYSTEM")
    print("=" * 80)
    print()
    
    # Step 1: Generate Sample Forensic Data
    print("[1] Generating Sample Forensic Data...")
    print("-" * 80)
    data = save_sample_data('./logs')
    print()
    
    # Step 2: Initialize Incident Response System
    print("[2] Initializing Incident Response System...")
    print("-" * 80)
    
    case_details = {
        'case_id': 'IR-2026-001',
        'incident_type': 'Suspected Data Exfiltration',
        'organization': 'Acme Corporation',
        'investigator': 'Digital Forensics Team',
        'executive_summary': '''
A potential data breach was detected on February 9, 2026, involving unauthorized 
access to workstation WORKSTATION-01. The incident appears to involve external 
threat actor gaining remote access, escalating privileges, and exfiltrating 
sensitive data through both network channels and removable media.

This automated forensic analysis correlates evidence from Windows Event Logs, 
network traffic captures, and USB device activity to reconstruct the attack 
timeline and identify the scope of compromise.
        ''',
        'conclusions': '''
CONCLUSIONS AND FINDINGS:
------------------------

The forensic timeline analysis reveals a coordinated attack with the following 
key observations:

1. INITIAL ACCESS: External RDP connection from IP 198.51.100.89 to internal 
   workstation at approximately [TIME]. The connection was successful using 
   credentials for account "attacker@external.com".

2. PRIVILEGE ESCALATION: Within 5 minutes of initial access, the attacker 
   obtained elevated privileges (Event ID 4672), indicating either credential 
   theft or exploitation of a privilege escalation vulnerability.

3. PERSISTENCE MECHANISM: A scheduled task was created (Event ID 4698) to 
   maintain persistent access to the compromised system.

4. DATA EXFILTRATION - NETWORK: Multiple large data transfers (2-5 MB each) 
   were observed to external IP 203.0.113.45 over HTTPS (port 443), totaling 
   approximately 15-20 MB of data.

5. DATA EXFILTRATION - REMOVABLE MEDIA: A Kingston DataTraveler USB device 
   was connected and used for data transfer approximately 35 minutes after 
   initial access, representing an additional exfiltration vector.

RECOMMENDATIONS:
---------------

IMMEDIATE ACTIONS:
• Isolate WORKSTATION-01 from the network immediately
• Disable remote access for account "attacker@external.com"
• Block external IP addresses 198.51.100.89 and 203.0.113.45 at firewall
• Reset credentials for all administrative accounts
• Scan for and remove scheduled tasks created during the incident window

SHORT-TERM ACTIONS:
• Conduct full malware analysis on WORKSTATION-01
• Review logs for lateral movement to other systems
• Identify and secure data that may have been exfiltrated
• Implement multi-factor authentication for all remote access
• Enable USB device logging and control policies

LONG-TERM ACTIONS:
• Review and strengthen remote access policies
• Implement network segmentation to limit lateral movement
• Deploy EDR solution for enhanced endpoint visibility
• Conduct security awareness training on phishing and social engineering
• Implement data loss prevention (DLP) controls
• Regular review of privileged account usage

EVIDENCE PRESERVATION:
All evidence has been cryptographically hashed and chain of custody maintained.
Further analysis may be required to determine the full extent of data compromise.
        '''
    }
    
    system = IncidentResponseSystem('IR-2026-001', case_details)
    
    # Register evidence files
    system.add_evidence_file('./logs/windows_events.json')
    system.add_evidence_file('./logs/network_traffic.json')
    system.add_evidence_file('./logs/usb_activity.json')
    
    print(f"Case ID: {case_details['case_id']}")
    print(f"Incident Type: {case_details['incident_type']}")
    print(f"Organization: {case_details['organization']}")
    print()
    
    # Step 3: Ingest Forensic Data
    print("[3] Ingesting Forensic Evidence...")
    print("-" * 80)
    
    system.ingest_forensic_data(
        windows_logs=data['windows_events'],
        network_logs=data['network_traffic'],
        usb_logs=data['usb_activity']
    )
    
    total_events = (len(data['windows_events']) + 
                   len(data['network_traffic']) + 
                   len(data['usb_activity']))
    
    print(f"Total events ingested: {total_events}")
    print(f"  • Windows Event Logs: {len(data['windows_events'])}")
    print(f"  • Network Traffic Logs: {len(data['network_traffic'])}")
    print(f"  • USB Activity Logs: {len(data['usb_activity'])}")
    print()
    
    # Step 4: Verify Evidence Integrity
    print("[4] Verifying Evidence Integrity...")
    print("-" * 80)
    
    manifest = EvidenceIntegrity.verify_chain_of_custody(system.evidence_files)
    for filepath, hashes in manifest.items():
        print(f"\nFile: {filepath}")
        print(f"  SHA-256: {hashes['sha256'][:64]}")
        print(f"  MD5:     {hashes['md5']}")
    print()
    
    # Step 5: Analyze and Generate Reports
    print("[5] Reconstructing Timeline and Generating Reports...")
    print("-" * 80)
    
    results = system.analyze_and_report('./output')
    
    print(f"\nAnalysis Complete!")
    print(f"  • Timeline events: {len(results['timeline'])}")
    print(f"  • Attack stages identified: {len(results['summary']['attack_stages'])}")
    print(f"  • Critical events: {results['summary']['severity_breakdown'].get('Critical', 0)}")
    print(f"  • High severity events: {results['summary']['severity_breakdown'].get('High', 0)}")
    print()
    
    # Display attack stage breakdown
    print("Attack Stage Distribution:")
    for stage, count in results['summary']['attack_stages'].items():
        print(f"  • {stage}: {count} events")
    print()
    
    # Step 6: Output Files Generated
    print("[6] Generated Output Files:")
    print("-" * 80)
    print(f"  ✓ Interactive Timeline: {results['html_path']}")
    print(f"  ✓ Forensic Report:      {results['report_path']}")
    print(f"  ✓ JSON Export:          {results['json_path']}")
    print()
    
    # Display critical events
    print("[7] Critical Events Summary:")
    print("-" * 80)
    critical_events = [e for e in results['timeline'] if e.severity in ['Critical', 'High']]
    
    for i, event in enumerate(critical_events[:10], 1):
        print(f"\n[{i}] {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {event.severity}")
        print(f"    Source: {event.source}")
        print(f"    Stage:  {event.attack_stage or 'Unknown'}")
        print(f"    Desc:   {event.description}")
        if event.ioc_tags:
            print(f"    IOCs:   {', '.join(event.ioc_tags)}")
    
    if len(critical_events) > 10:
        print(f"\n... and {len(critical_events) - 10} more critical events")
    
    print()
    print("=" * 80)
    print(" ANALYSIS COMPLETE")
    print("=" * 80)
    print()
    print("Next Steps:")
    print("  1. Review the interactive timeline visualization in your browser")
    print("  2. Read the comprehensive forensic report")
    print("  3. Export the JSON data for further analysis")
    print("  4. Implement the recommended security measures")
    print()
    
    return results


def display_help():
    """Display usage information"""
    print("""
Digital Incident Response and Timeline Reconstruction System
============================================================

USAGE:
    python demo.py

DESCRIPTION:
    This demonstration showcases a complete digital forensics and incident
    response (DFIR) workflow including:
    
    • Multi-source log ingestion (Windows, Network, USB)
    • Event normalization and correlation
    • Timeline reconstruction with attack stage classification
    • Evidence integrity verification (SHA-256, MD5)
    • Interactive HTML visualization
    • Comprehensive forensic reporting
    
OUTPUTS:
    • output/timeline_visualization.html - Interactive timeline
    • output/forensic_report.txt - Detailed investigation report
    • output/timeline_export.json - Structured data export
    
FEATURES:
    ✓ MITRE ATT&CK framework integration
    ✓ Cryptographic evidence verification
    ✓ Automated IOC detection
    ✓ Multi-stage attack reconstruction
    ✓ Chain of custody maintenance
    ✓ Professional forensic reporting
    
For more information, see the included documentation.
    """)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        display_help()
    else:
        try:
            demonstrate_incident_response()
        except Exception as e:
            print(f"\n❌ Error during analysis: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
