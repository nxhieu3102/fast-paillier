#!/usr/bin/env python3
"""
Simple performance summary for CGGMP21 protocol benchmarks
Extracts key metrics for the requested protocols - no external dependencies
"""

import re
import csv
from typing import Dict

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

def extract_performance_data(file_path: str) -> Dict:
    """Extract performance data from log file"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    results = {}
    
    # Split content by n values
    n_sections = re.split(r'\nn = (\d+)', content)
    
    for i in range(1, len(n_sections), 2):
        n = int(n_sections[i])
        section_content = n_sections[i + 1]
        
        results[n] = {}
        
        # Extract Threshold DKG
        match = re.search(r'Threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Threshold DKG'] = parse_time_to_ms(match.group(1))
        
        # Extract Auxiliary data generation protocol
        match = re.search(r'Auxiliary data generation protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Auxiliary data generation protocol'] = parse_time_to_ms(match.group(1))
        
        # Extract Threshold signing protocol (note the lowercase 's')
        match = re.search(r'Threshold signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Threshold signing protocol'] = parse_time_to_ms(match.group(1))
        
        # Extract Hierarchical threshold signing protocol
        match = re.search(r'Hierarchical threshold signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Hierarchical threshold signing protocol'] = parse_time_to_ms(match.group(1))
    
    return results

def print_detailed_summary(original_data: Dict, optimized_data: Dict):
    """Print detailed performance summary grouped by protocol"""
    print("=" * 100)
    print("CGGMP21 PROTOCOL PERFORMANCE SUMMARY")
    print("=" * 100)
    
    protocols = [
        'Threshold DKG', 
        'Auxiliary data generation protocol', 
        'Threshold signing protocol', 
        'Hierarchical threshold signing protocol'
    ]
    
    for protocol in protocols:
        print(f"\n🔧 {protocol}")
        print("=" * 70)
        
        # Get all n values that have this protocol in either original or optimized data
        all_n_values = set()
        for n in original_data.keys():
            if protocol in original_data[n]:
                all_n_values.add(n)
        for n in optimized_data.keys():
            if protocol in optimized_data[n]:
                all_n_values.add(n)
        
        for n in sorted(all_n_values):
            original_time = original_data.get(n, {}).get(protocol, None)
            optimized_time = optimized_data.get(n, {}).get(protocol, None)
            
            if original_time is not None and optimized_time is not None:
                improvement = ((original_time - optimized_time) / original_time) * 100
                print(f"  n = {n}:")
                print(f"    Original:  {original_time:>8.2f} ms")
                print(f"    Optimized: {optimized_time:>8.2f} ms")
                print(f"    Improvement: {improvement:>5.1f}%")
            elif original_time is not None:
                print(f"  n = {n}:")
                print(f"    Original:  {original_time:>8.2f} ms")
                print(f"    Optimized: {'N/A':>8}")
            elif optimized_time is not None:
                print(f"  n = {n}:")
                print(f"    Original:  {'N/A':>8}")
                print(f"    Optimized: {optimized_time:>8.2f} ms")
            
            print()

def create_summary_table(original_data: Dict, optimized_data: Dict) -> list:
    """Create a summary table with original and optimized performance, grouped by protocol"""
    rows = []
    
    protocols = [
        'Threshold DKG', 
        'Auxiliary data generation protocol', 
        'Threshold signing protocol', 
        'Hierarchical threshold signing protocol'
    ]
    
    for protocol in protocols:
        # Get all n values that have this protocol in either original or optimized data
        all_n_values = set()
        for n in original_data.keys():
            if protocol in original_data[n]:
                all_n_values.add(n)
        for n in optimized_data.keys():
            if protocol in optimized_data[n]:
                all_n_values.add(n)
        
        for n in sorted(all_n_values):
            original_time = original_data.get(n, {}).get(protocol, None)
            optimized_time = optimized_data.get(n, {}).get(protocol, None)
            
            if original_time is not None and optimized_time is not None:
                improvement = ((original_time - optimized_time) / original_time) * 100
                rows.append({
                    'n': n,
                    'Protocol': protocol,
                    'Original (ms)': f"{original_time:.2f}",
                    'Optimized (ms)': f"{optimized_time:.2f}",
                    'Improvement (%)': f"{improvement:.1f}%"
                })
            elif original_time is not None:
                rows.append({
                    'n': n,
                    'Protocol': protocol,
                    'Original (ms)': f"{original_time:.2f}",
                    'Optimized (ms)': 'N/A',
                    'Improvement (%)': 'N/A'
                })
            elif optimized_time is not None:
                rows.append({
                    'n': n,
                    'Protocol': protocol,
                    'Original (ms)': 'N/A',
                    'Optimized (ms)': f"{optimized_time:.2f}",
                    'Improvement (%)': 'N/A'
                })
    
    return rows

def print_table(rows: list):
    """Print table in a formatted way"""
    if not rows:
        print("No data to display")
        return
    
    # Table headers
    headers = ['n', 'Protocol', 'Original (ms)', 'Optimized (ms)', 'Improvement (%)']
    
    # Calculate column widths
    col_widths = [len(header) for header in headers]
    for row in rows:
        col_widths[0] = max(col_widths[0], len(str(row['n'])))
        col_widths[1] = max(col_widths[1], len(row['Protocol']))
        col_widths[2] = max(col_widths[2], len(row['Original (ms)']))
        col_widths[3] = max(col_widths[3], len(row['Optimized (ms)']))
        col_widths[4] = max(col_widths[4], len(row['Improvement (%)']))
    
    # Print header
    header_row = "| " + " | ".join(f"{headers[i]:{col_widths[i]}}" for i in range(len(headers))) + " |"
    print(header_row)
    print("|" + "|".join("-" * (col_widths[i] + 2) for i in range(len(headers))) + "|")
    
    # Print rows
    for row in rows:
        data_row = "| " + " | ".join([
            f"{row['n']:{col_widths[0]}}",
            f"{row['Protocol']:{col_widths[1]}}",
            f"{row['Original (ms)']:{col_widths[2]}}",
            f"{row['Optimized (ms)']:{col_widths[3]}}",
            f"{row['Improvement (%)']:{col_widths[4]}}"
        ]) + " |"
        print(data_row)

def save_to_csv(rows: list, filename: str):
    """Save results to CSV file"""
    if not rows:
        print("No data to save")
        return
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['n', 'Protocol', 'Original (ms)', 'Optimized (ms)', 'Improvement (%)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def main():
    # File paths - Update these paths according to your file locations
    original_file = "../fork-cggmp21/logs/measure-perf/202507152140_optimized.txt"
    optimized_file = "../fork-cggmp21/logs/measure-perf/202507142140_optimized_batch.txt"
    
    print("Parsing performance logs...")
    print(f"Original file: {original_file}")
    print(f"Optimized file: {optimized_file}")
    
    # Parse both files
    original_data = extract_performance_data(original_file)
    optimized_data = extract_performance_data(optimized_file)
    
    # Print detailed summary
    print_detailed_summary(original_data, optimized_data)
    
    # Create and display summary table
    rows = create_summary_table(original_data, optimized_data)
    
    print("\n" + "=" * 100)
    print("SUMMARY TABLE")
    print("=" * 100)
    print_table(rows)
    
    # Save to CSV
    csv_filename = "performance_summary_updated.csv"
    save_to_csv(rows, csv_filename)
    print(f"\nResults saved to {csv_filename}")
    
    # Print performance improvements by protocol
    print("\n" + "=" * 100)
    print("AVERAGE PERFORMANCE IMPROVEMENTS BY PROTOCOL")
    print("=" * 100)
    
    protocol_improvements = {}
    for row in rows:
        if row['Improvement (%)'] != 'N/A':
            protocol = row['Protocol']
            improvement = float(row['Improvement (%)'].rstrip('%'))
            if protocol not in protocol_improvements:
                protocol_improvements[protocol] = []
            protocol_improvements[protocol].append(improvement)
    
    for protocol, improvements in protocol_improvements.items():
        avg_improvement = sum(improvements) / len(improvements)
        print(f"{protocol}: {avg_improvement:.1f}% average improvement")
    
    # Print summary of extracted data
    print("\n" + "=" * 100)
    print("DATA EXTRACTION SUMMARY")
    print("=" * 100)
    print("Extracted data for n values:", sorted(set(original_data.keys()) | set(optimized_data.keys())))
    print("Protocols analyzed:")
    for i, protocol in enumerate([
        'Threshold DKG', 
        'Auxiliary data generation protocol', 
        'Threshold signing protocol', 
        'Hierarchical threshold signing protocol'
    ], 1):
        print(f"  {i}. {protocol}")

if __name__ == "__main__":
    main() 
