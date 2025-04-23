"""
Test script for Sigma rule: Detect VHD/VHDX Mount (Potential CVE-2025-24985 Exploit)
Rule ID: c4ce1282-7b53-4f7a-914d-ee48cfa0288b

This script tests for VHD/VHDX file operations with EventIDs 1 and 12 in the
Microsoft-Windows-VHDMP-Operational event log channel.
"""

import json
import os
from datetime import datetime

# Configuration
LOG_FILE = 'combined_sample_logs.json'
RESULTS_FILE = f'vhd_mount_detection_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'

# Load sample logs
try:
    with open(LOG_FILE, 'r') as f:
        logs = json.load(f)
    print(f"Successfully loaded {len(logs)} log entries from {LOG_FILE}")
except FileNotFoundError:
    print(f"Error: Log file '{LOG_FILE}' not found")
    exit(1)
except json.JSONDecodeError:
    print(f"Error: Invalid JSON format in log file '{LOG_FILE}'")
    exit(1)

# Define detection logic specific to CVE-2025-24985 VHD mount detection
def matches_rule(log):
    """
    Implements detection logic for the Sigma rule:
    'Detect VHD/VHDX Mount (Potential CVE-2025-24985 Exploit)'
    
    Returns: (matched, details)
    - matched: Boolean indicating if the log entry matched the rule
    - details: Dictionary with details about why it matched or didn't match
    """
    # Extract relevant fields
    event_id = log.get('EventID')
    vhd_filename = log.get('EventData', {}).get('VhdFileName', '')
    
    # Check conditions
    is_relevant_event = event_id in ['1', '12', 1, 12]  # Support both string and integer formats
    has_vhd_extension = (vhd_filename.lower().endswith('.vhd') or 
                         vhd_filename.lower().endswith('.vhdx'))
    
    # Determine if rule matches
    matched = is_relevant_event and has_vhd_extension
    
    # Return match result and details
    return matched, {
        "event_id_match": is_relevant_event,
        "vhd_extension_match": has_vhd_extension,
        "event_id": event_id,
        "vhd_filename": vhd_filename
    }

# Test each log entry
matches = 0
total = len(logs)
results = []

print("\nTesting logs against rule 'Detect VHD/VHDX Mount (Potential CVE-2025-24985 Exploit)'...")
print("-" * 80)

for i, log in enumerate(logs):
    matched, details = matches_rule(log)
    
    if matched:
        matches += 1
        status = "DETECTED (matches rule)"
    else:
        status = "Not detected"
    
    result = f"Log {i + 1}: {status}"
    detail_str = f"  Details: EventID={details['event_id']}, VhdFileName={details['vhd_filename']}"
    
    print(result)
    print(detail_str)
    
    # Store results for later writing to file
    results.append(f"{result}\n{detail_str}\n")

# Print summary
match_percentage = (matches/total)*100 if total > 0 else 0
print("\n" + "=" * 80)
print(f"SUMMARY: {matches}/{total} logs matched the rule ({match_percentage:.1f}%)")
print("=" * 80)

# Optionally save results to file
try:
    with open(RESULTS_FILE, 'w') as f:
        f.write(f"Test Results for Sigma Rule: Detect VHD/VHDX Mount (Potential CVE-2025-24985 Exploit)\n")
        f.write(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Log File: {LOG_FILE}\n")
        f.write("=" * 80 + "\n\n")
        
        for result in results:
            f.write(result + "\n")
            
        f.write("\n" + "=" * 80 + "\n")
        f.write(f"SUMMARY: {matches}/{total} logs matched the rule ({match_percentage:.1f}%)\n")
    
    print(f"\nResults saved to {RESULTS_FILE}")
except Exception as e:
    print(f"Error saving results to file: {e}")