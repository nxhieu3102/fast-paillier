#!/usr/bin/env python3
"""
Single-file performance analyzer for CGGMP21 protocol benchmarks
Analyzes performance metrics for different n values and protocols
"""

import re
import csv
import sys
from typing import Dict, List

def parse_time_to_ms(time_str: str) -> float:
    """Convert time string to milliseconds"""
    time_str = time_str.strip()
    
    if time_str.endswith('ns'):
        return float(time_str[:-2]) / 1_000_000
    elif time_str.endswith('µs'):
        return float(time_str[:-2]) / 1_000
    elif time_str.endswith('ms'):
        return float(time_str[:-2])
    elif time_str.endswith('s'):
        return float(time_str[:-1]) * 1_000
    else:
        return float(time_str)

def extract_detailed_performance_data(file_path: str) -> Dict:
    """Extract detailed performance data from log file"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    results = {}
    
    # Split content by n values
    n_sections = re.split(r'\nn = (\d+)', content)
    
    for i in range(1, len(n_sections), 2):
        n = int(n_sections[i])
        section_content = n_sections[i + 1]
        
        results[n] = {}
        
        # Define protocols to extract
        protocols = {
            'Non-threshold DKG': r'Non-threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete',
            'Threshold DKG': r'Threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete',
            'Hierarchical threshold DKG': r'Hierarchical threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete',
            'Auxiliary data generation': r'Auxiliary data generation protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
            'Signing protocol': r'Signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
            'Threshold signing protocol': r'Threshold signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
            'Hierarchical threshold signing protocol': r'Hierarchical threshold signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete'
        }
        
        # Extract all protocols found in this section
        for protocol_name, pattern in protocols.items():
            match = re.search(pattern, section_content)
            if match:
                results[n][protocol_name] = parse_time_to_ms(match.group(1))
    
    return results

def analyze_scaling(data: Dict, protocol_name: str) -> Dict:
    """Analyze how a protocol scales with n"""
    protocol_data = {}
    for n in sorted(data.keys()):
        if protocol_name in data[n]:
            protocol_data[n] = data[n][protocol_name]
    
    if len(protocol_data) < 2:
        return {}
    
    # Calculate scaling factors
    scaling_info = {}
    n_values = sorted(protocol_data.keys())
    
    for i in range(1, len(n_values)):
        n1, n2 = n_values[i-1], n_values[i]
        time1, time2 = protocol_data[n1], protocol_data[n2]
        
        # Calculate scaling factor
        n_ratio = n2 / n1
        time_ratio = time2 / time1
        
        scaling_info[f"{n1} to {n2}"] = {
            'n_ratio': n_ratio,
            'time_ratio': time_ratio,
            'scaling_factor': time_ratio / n_ratio
        }
    
    return scaling_info

def print_summary(data: Dict, file_name: str):
    """Print a comprehensive summary of the performance data"""
    print("=" * 100)
    print(f"CGGMP21 PROTOCOL PERFORMANCE ANALYSIS: {file_name}")
    print("=" * 100)
    
    # Print performance for each n
    for n in sorted(data.keys()):
        print(f"\n📊 n = {n}")
        print("=" * 60)
        
        protocols = data[n]
        for protocol_name, time_ms in protocols.items():
            if time_ms < 1000:
                print(f"  {protocol_name}: {time_ms:>8.2f} ms")
            else:
                print(f"  {protocol_name}: {time_ms:>8.2f} ms ({time_ms/1000:.2f}s)")
    
    # Print scaling analysis
    print("\n" + "=" * 100)
    print("SCALING ANALYSIS")
    print("=" * 100)
    
    # Find common protocols across all n values
    common_protocols = set(data[list(data.keys())[0]].keys())
    for n in data.keys():
        common_protocols = common_protocols.intersection(set(data[n].keys()))
    
    for protocol in common_protocols:
        scaling_info = analyze_scaling(data, protocol)
        if scaling_info:
            print(f"\n{protocol}:")
            for transition, info in scaling_info.items():
                print(f"  {transition}: {info['time_ratio']:.2f}x time increase for {info['n_ratio']:.2f}x parties")
                if info['scaling_factor'] > 1.5:
                    print(f"    ⚠️  Scaling factor: {info['scaling_factor']:.2f} (worse than linear)")
                elif info['scaling_factor'] > 1.0:
                    print(f"    ✓  Scaling factor: {info['scaling_factor']:.2f} (linear)")
                else:
                    print(f"    ✓  Scaling factor: {info['scaling_factor']:.2f} (better than linear)")

def create_csv_report(data: Dict, filename: str):
    """Create a CSV report with all performance data"""
    rows = []
    
    for n in sorted(data.keys()):
        for protocol_name, time_ms in data[n].items():
            rows.append({
                'n': n,
                'Protocol': protocol_name,
                'Time (ms)': f"{time_ms:.2f}",
                'Time (s)': f"{time_ms/1000:.3f}"
            })
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['n', 'Protocol', 'Time (ms)', 'Time (s)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 single_file_analyzer.py <log_file_path>")
        print("Example: python3 single_file_analyzer.py ../cggmp21/logs/measure-perf/202507142140_original.txt")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        print(f"Analyzing performance log: {file_path}")
        data = extract_detailed_performance_data(file_path)
        
        if not data:
            print("No performance data found in the file.")
            sys.exit(1)
        
        # Print summary
        print_summary(data, file_path.split('/')[-1])
        
        # Create CSV report
        csv_filename = f"performance_report_{file_path.split('/')[-1].replace('.txt', '.csv')}"
        create_csv_report(data, csv_filename)
        print(f"\nDetailed report saved to: {csv_filename}")
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
