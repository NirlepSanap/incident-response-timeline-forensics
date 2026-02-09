#!/usr/bin/env python3
"""
Sample Forensic Data Generator
Generates realistic forensic log data for demonstration purposes
"""

import json
from datetime import datetime, timedelta
import random


def generate_sample_windows_events(base_time: datetime, num_events: int = 50):
    """Generate sample Windows Event Log entries"""
    events = []
    
    event_templates = [
        # Normal authentication
        {
            'event_id': '4624',
            'level': 'Information',
            'channel': 'Security',
            'message': 'An account was successfully logged on'
        },
        # Privilege escalation
        {
            'event_id': '4672',
            'level': 'Warning',
            'channel': 'Security',
            'message': 'Special privileges assigned to new logon'
        },
        # Process creation
        {
            'event_id': '4688',
            'level': 'Information',
            'channel': 'Security',
            'message': 'A new process has been created'
        },
        # Scheduled task created (persistence)
        {
            'event_id': '4698',
            'level': 'Warning',
            'channel': 'Security',
            'message': 'A scheduled task was created'
        },
        # Account logoff
        {
            'event_id': '4634',
            'level': 'Information',
            'channel': 'Security',
            'message': 'An account was logged off'
        }
    ]
    
    users = ['SYSTEM', 'Administrator', 'JohnDoe', 'attacker@external.com', 'ServiceAccount']
    computers = ['WORKSTATION-01', 'SERVER-DC01', 'LAPTOP-HR02']
    
    current_time = base_time
    
    for i in range(num_events):
        template = random.choice(event_templates)
        
        event = {
            'timestamp': current_time.isoformat(),
            'event_id': template['event_id'],
            'level': template['level'],
            'channel': template['channel'],
            'message': template['message'],
            'computer': random.choice(computers),
            'user': random.choice(users),
            'process_id': random.randint(1000, 9999)
        }
        
        events.append(event)
        current_time += timedelta(seconds=random.randint(5, 300))
    
    return events


def generate_sample_network_traffic(base_time: datetime, num_events: int = 40):
    """Generate sample network traffic/firewall log entries"""
    events = []
    
    internal_ips = ['192.168.1.10', '192.168.1.15', '192.168.1.20', '10.0.0.5']
    external_ips = ['203.0.113.45', '198.51.100.89', '192.0.2.123', '185.220.101.50']
    
    protocols = ['TCP', 'UDP', 'ICMP']
    common_ports = [80, 443, 22, 3389, 445, 139, 53, 21, 23]
    
    current_time = base_time
    
    for i in range(num_events):
        is_outbound = random.random() > 0.5
        
        if is_outbound:
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
        else:
            src_ip = random.choice(external_ips)
            dst_ip = random.choice(internal_ips)
        
        protocol = random.choice(protocols)
        dst_port = random.choice(common_ports)
        
        # Simulate some suspicious activities
        severity = 'Information'
        action = 'allowed'
        bytes_transferred = random.randint(1000, 100000)
        
        if dst_port in [22, 23, 3389] and src_ip in external_ips:
            severity = 'Warning'
        
        if dst_port in [80, 443] and bytes_transferred > 500000:
            severity = 'Critical'
            bytes_transferred = random.randint(1000000, 5000000)
        
        if random.random() > 0.9:
            action = 'blocked'
            severity = 'Warning'
        
        event = {
            'timestamp': current_time.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(49152, 65535),
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes': bytes_transferred,
            'action': action,
            'severity': severity
        }
        
        events.append(event)
        current_time += timedelta(seconds=random.randint(10, 180))
    
    return events


def generate_sample_usb_activity(base_time: datetime, num_events: int = 15):
    """Generate sample USB device activity logs"""
    events = []
    
    devices = [
        {
            'device_id': 'USB\\VID_0951&PID_1666',
            'device_name': 'Kingston DataTraveler 3.0',
            'serial_number': 'AA0123456789'
        },
        {
            'device_id': 'USB\\VID_058F&PID_6387',
            'device_name': 'Generic USB Storage',
            'serial_number': 'BB9876543210'
        },
        {
            'device_id': 'USB\\VID_0781&PID_5581',
            'device_name': 'SanDisk Ultra USB 3.0',
            'serial_number': 'CC1122334455'
        }
    ]
    
    actions = ['connected', 'disconnected', 'data_transfer']
    users = ['JohnDoe', 'Administrator', 'attacker@external.com']
    
    current_time = base_time + timedelta(minutes=30)  # USB activity happens later
    
    for i in range(num_events):
        device = random.choice(devices)
        action = random.choice(actions)
        
        severity = 'Warning'
        if action == 'data_transfer':
            severity = 'Critical'
        elif action == 'disconnected':
            severity = 'Information'
        
        event = {
            'timestamp': current_time.isoformat(),
            'device_id': device['device_id'],
            'device_name': device['device_name'],
            'serial_number': device['serial_number'],
            'action': action,
            'user': random.choice(users),
            'volume_name': f"USBDRIVE{random.randint(1,9)}" if action != 'disconnected' else None,
            'severity': severity
        }
        
        events.append(event)
        current_time += timedelta(seconds=random.randint(30, 600))
    
    return events


def generate_attack_scenario(base_time: datetime):
    """Generate a realistic attack scenario with coordinated events"""
    
    scenario_events = {
        'windows_events': [],
        'network_events': [],
        'usb_events': []
    }
    
    # Phase 1: Initial Access (External RDP connection)
    t = base_time
    scenario_events['network_events'].append({
        'timestamp': t.isoformat(),
        'src_ip': '198.51.100.89',
        'dst_ip': '192.168.1.10',
        'src_port': 52341,
        'dst_port': 3389,
        'protocol': 'TCP',
        'bytes': 4567,
        'action': 'allowed',
        'severity': 'Warning'
    })
    
    scenario_events['windows_events'].append({
        'timestamp': (t + timedelta(seconds=5)).isoformat(),
        'event_id': '4624',
        'level': 'Information',
        'channel': 'Security',
        'message': 'An account was successfully logged on',
        'computer': 'WORKSTATION-01',
        'user': 'attacker@external.com',
        'process_id': 2341
    })
    
    # Phase 2: Privilege Escalation
    t += timedelta(minutes=5)
    scenario_events['windows_events'].append({
        'timestamp': t.isoformat(),
        'event_id': '4672',
        'level': 'Warning',
        'channel': 'Security',
        'message': 'Special privileges assigned to new logon',
        'computer': 'WORKSTATION-01',
        'user': 'attacker@external.com',
        'process_id': 2341
    })
    
    # Phase 3: Persistence - Scheduled Task
    t += timedelta(minutes=2)
    scenario_events['windows_events'].append({
        'timestamp': t.isoformat(),
        'event_id': '4698',
        'level': 'Warning',
        'channel': 'Security',
        'message': 'A scheduled task was created',
        'computer': 'WORKSTATION-01',
        'user': 'attacker@external.com',
        'process_id': 3456
    })
    
    # Phase 4: Data Collection and Exfiltration via Network
    t += timedelta(minutes=10)
    for i in range(5):
        scenario_events['network_events'].append({
            'timestamp': (t + timedelta(seconds=i*30)).isoformat(),
            'src_ip': '192.168.1.10',
            'dst_ip': '203.0.113.45',
            'src_port': 52000 + i,
            'dst_port': 443,
            'protocol': 'TCP',
            'bytes': random.randint(2000000, 5000000),
            'action': 'allowed',
            'severity': 'Critical'
        })
    
    # Phase 5: Data Exfiltration via USB
    t += timedelta(minutes=15)
    scenario_events['usb_events'].append({
        'timestamp': t.isoformat(),
        'device_id': 'USB\\VID_0951&PID_1666',
        'device_name': 'Kingston DataTraveler 3.0',
        'serial_number': 'AA0123456789',
        'action': 'connected',
        'user': 'attacker@external.com',
        'volume_name': 'USBDRIVE1',
        'severity': 'High'
    })
    
    scenario_events['usb_events'].append({
        'timestamp': (t + timedelta(minutes=5)).isoformat(),
        'device_id': 'USB\\VID_0951&PID_1666',
        'device_name': 'Kingston DataTraveler 3.0',
        'serial_number': 'AA0123456789',
        'action': 'data_transfer',
        'user': 'attacker@external.com',
        'volume_name': 'USBDRIVE1',
        'severity': 'Critical'
    })
    
    scenario_events['usb_events'].append({
        'timestamp': (t + timedelta(minutes=8)).isoformat(),
        'device_id': 'USB\\VID_0951&PID_1666',
        'device_name': 'Kingston DataTraveler 3.0',
        'serial_number': 'AA0123456789',
        'action': 'disconnected',
        'user': 'attacker@external.com',
        'volume_name': None,
        'severity': 'Information'
    })
    
    # Phase 6: Cover Tracks - Logoff
    t += timedelta(minutes=12)
    scenario_events['windows_events'].append({
        'timestamp': t.isoformat(),
        'event_id': '4634',
        'level': 'Information',
        'channel': 'Security',
        'message': 'An account was logged off',
        'computer': 'WORKSTATION-01',
        'user': 'attacker@external.com',
        'process_id': 2341
    })
    
    return scenario_events


def save_sample_data(output_dir: str = './logs'):
    """Generate and save all sample forensic data"""
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    base_time = datetime.now() - timedelta(hours=2)
    
    # Generate background noise
    windows_logs = generate_sample_windows_events(base_time, 30)
    network_logs = generate_sample_network_traffic(base_time, 25)
    usb_logs = generate_sample_usb_activity(base_time, 8)
    
    # Add attack scenario
    attack_scenario = generate_attack_scenario(base_time + timedelta(minutes=20))
    windows_logs.extend(attack_scenario['windows_events'])
    network_logs.extend(attack_scenario['network_events'])
    usb_logs.extend(attack_scenario['usb_events'])
    
    # Sort by timestamp
    windows_logs.sort(key=lambda x: x['timestamp'])
    network_logs.sort(key=lambda x: x['timestamp'])
    usb_logs.sort(key=lambda x: x['timestamp'])
    
    # Save to JSON files
    with open(f'{output_dir}/windows_events.json', 'w') as f:
        json.dump(windows_logs, f, indent=2)
    
    with open(f'{output_dir}/network_traffic.json', 'w') as f:
        json.dump(network_logs, f, indent=2)
    
    with open(f'{output_dir}/usb_activity.json', 'w') as f:
        json.dump(usb_logs, f, indent=2)
    
    print(f"Sample forensic data generated in {output_dir}/")
    print(f"  - Windows Events: {len(windows_logs)} entries")
    print(f"  - Network Traffic: {len(network_logs)} entries")
    print(f"  - USB Activity: {len(usb_logs)} entries")
    
    return {
        'windows_events': windows_logs,
        'network_traffic': network_logs,
        'usb_activity': usb_logs
    }


if __name__ == "__main__":
    save_sample_data()
