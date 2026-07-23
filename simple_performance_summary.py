#!/usr/bin/env python3
"""
Simple performance summary for CGGMP21 protocol benchmarks
Extracts key metrics for the requested protocols
"""

import re
import pandas as pd
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
        
        # Extract Non-threshold DKG
        match = re.search(r'Non-threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Non-threshold DKG'] = parse_time_to_ms(match.group(1))
        
        # Extract Threshold DKG  
        match = re.search(r'Threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Threshold DKG'] = parse_time_to_ms(match.group(1))
        
        # Extract Auxiliary data generation protocol
        match = re.search(r'Auxiliary data generation protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Auxiliary data generation'] = parse_time_to_ms(match.group(1))
        
        # Extract Signing protocol
        match = re.search(r'Signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete', section_content)
        if match:
            results[n]['Signing protocol'] = parse_time_to_ms(match.group(1))
    
    return results

def create_summary_table(original_data: Dict, optimized_data: Dict) -> pd.DataFrame:
    """Create a summary table with original and optimized performance"""
    rows = []
    
    protocols = ['Non-threshold DKG', 'Threshold DKG', 'Auxiliary data generation', 'Signing protocol']
    
    for n in sorted(original_data.keys()):
        for protocol in protocols:
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
    
    return pd.DataFrame(rows)

def print_detailed_summary(original_data: Dict, optimized_data: Dict):
    """Print detailed performance summary"""
    print("=" * 100)
    print("CGGMP21 PROTOCOL PERFORMANCE SUMMARY")
    print("=" * 100)
    
    protocols = ['Non-threshold DKG', 'Threshold DKG', 'Auxiliary data generation', 'Signing protocol']
    
    for n in sorted(original_data.keys()):
        print(f"\n📊 n = {n}")
        print("=" * 60)
        
        for protocol in protocols:
            original_time = original_data.get(n, {}).get(protocol, None)
            optimized_time = optimized_data.get(n, {}).get(protocol, None)
            
            if original_time is not None and optimized_time is not None:
                improvement = ((original_time - optimized_time) / original_time) * 100
                print(f"  {protocol}:")
                print(f"    Original:  {original_time:>8.2f} ms")
                print(f"    Optimized: {optimized_time:>8.2f} ms")
                print(f"    Improvement: {improvement:>5.1f}%")
            elif original_time is not None:
                print(f"  {protocol}:")
                print(f"    Original:  {original_time:>8.2f} ms")
                print(f"    Optimized: {'N/A':>8}")
            elif optimized_time is not None:
                print(f"  {protocol}:")
                print(f"    Original:  {'N/A':>8}")
                print(f"    Optimized: {optimized_time:>8.2f} ms")
            
            print()

def main():
    # File paths
    original_file = "cggmp21/logs/measure-perf/202507142140_original.txt"
    optimized_file = "fork-cggmp21/logs/measure-perf/202507142140_optimized.txt"
    
    print("Parsing performance logs...")
    
    # Parse both files
    original_data = extract_performance_data(original_file)
    optimized_data = extract_performance_data(optimized_file)
    
    # Print detailed summary
    print_detailed_summary(original_data, optimized_data)
    
    # Create and save summary table
    df = create_summary_table(original_data, optimized_data)
    
    print("\n" + "=" * 100)
    print("SUMMARY TABLE")
    print("=" * 100)
    print(df.to_string(index=False))
    
    # Save to CSV
    df.to_csv("performance_summary.csv", index=False)
    print(f"\nResults saved to performance_summary.csv")
    
    # Print performance improvements by protocol
    print("\n" + "=" * 100)
    print("AVERAGE PERFORMANCE IMPROVEMENTS BY PROTOCOL")
    print("=" * 100)
    
    protocol_improvements = {}
    for _, row in df.iterrows():
        if row['Improvement (%)'] != 'N/A':
            protocol = row['Protocol']
            improvement = float(row['Improvement (%)'].rstrip('%'))
            if protocol not in protocol_improvements:
                protocol_improvements[protocol] = []
            protocol_improvements[protocol].append(improvement)
    
    for protocol, improvements in protocol_improvements.items():
        avg_improvement = sum(improvements) / len(improvements)
        print(f"{protocol}: {avg_improvement:.1f}% average improvement")

if __name__ == "__main__":
    main() 
