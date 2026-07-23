#!/usr/bin/env python3
"""
Generate complete comparison table with mock baseline data
"""

import csv
import re
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

def calculate_mock_baseline(optimized_time: float, improvement_percent: float) -> float:
    """Calculate the mock baseline from optimized time and improvement percentage"""
    return optimized_time / (1 - improvement_percent / 100)

def main():
    # Previous improvement percentages for n=7
    previous_improvements = {
        'Non-threshold DKG': 1.1,
        'Threshold DKG': 1.2,
        'Auxiliary data generation': -1.5,  # This was a regression
        'Signing protocol': 26.4
    }
    
    # Extract new optimized data
    new_file = "../fork-cggmp21/logs/measure-perf/250623_13h55_disable_precomputable.txt"
    new_data = extract_performance_data(new_file)
    
    print("=" * 100)
    print("MOCK BASELINE COMPARISON FOR n=7 (NEW OPTIMIZED DATA)")
    print("=" * 100)
    print()
    
    if 7 not in new_data:
        print("Error: No data found for n=7 in the new file")
        return
    
    n7_data = new_data[7]
    
    # Generate comparison data
    comparison_data = []
    
    for protocol_name, improvement in previous_improvements.items():
        # Try to find matching protocol in new data
        optimized_time = None
        
        if protocol_name in n7_data:
            optimized_time = n7_data[protocol_name]
        elif protocol_name == 'Signing protocol' and 'Threshold signing protocol' in n7_data:
            # Map "Signing protocol" to "Threshold signing protocol"
            optimized_time = n7_data['Threshold signing protocol']
        
        if optimized_time is not None:
            mock_baseline = calculate_mock_baseline(optimized_time, improvement)
            
            comparison_data.append({
                'n': 7,
                'Protocol': protocol_name,
                'Mock Baseline (ms)': f"{mock_baseline:.2f}",
                'New Optimized (ms)': f"{optimized_time:.2f}",
                'Improvement (%)': f"{improvement:.1f}%"
            })
    
    # Display table
    print("Results based on improvement percentages from previous comparison:")
    print()
    
    # Print table header
    print("| n | Protocol                  | Mock Baseline (ms) | New Optimized (ms) | Improvement (%) |")
    print("|---|---------------------------|-------------------|-------------------|-----------------|")
    
    # Print data rows
    for row in comparison_data:
        print(f"| {row['n']} | {row['Protocol']:<25} | {row['Mock Baseline (ms)']:>16} | {row['New Optimized (ms)']:>16} | {row['Improvement (%)']:>13} |")
    
    # Save to CSV
    with open('mock_baseline_comparison_n7.csv', 'w', newline='') as csvfile:
        fieldnames = ['n', 'Protocol', 'Mock Baseline (ms)', 'New Optimized (ms)', 'Improvement (%)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in comparison_data:
            writer.writerow(row)
    
    print(f"\nResults saved to: mock_baseline_comparison_n7.csv")
    
    # Display key insights
    print("\n" + "=" * 100)
    print("KEY INSIGHTS:")
    print("=" * 100)
    
    print("🔍 Analysis based on new optimized data for n=7:")
    print()
    
    for row in comparison_data:
        protocol = row['Protocol']
        baseline = float(row['Mock Baseline (ms)'])
        optimized = float(row['New Optimized (ms)'])
        improvement = float(row['Improvement (%)'].rstrip('%'))
        
        if baseline < 1000:
            baseline_display = f"{baseline:.2f} ms"
        else:
            baseline_display = f"{baseline:.2f} ms ({baseline/1000:.2f}s)"
        
        if optimized < 1000:
            optimized_display = f"{optimized:.2f} ms"
        else:
            optimized_display = f"{optimized:.2f} ms ({optimized/1000:.2f}s)"
        
        print(f"• {protocol}:")
        print(f"  - Mock baseline: {baseline_display}")
        print(f"  - New optimized: {optimized_display}")
        print(f"  - Expected improvement: {improvement:.1f}%")
        print()
    
    print("📊 Performance Summary:")
    print("  - Signing protocol shows the most significant improvement (26.4%)")
    print("  - DKG protocols show modest improvements (1.1-1.2%)")
    print("  - Auxiliary data generation shows regression (-1.5%)")
    print()
    
    print("🔧 Calculation Method:")
    print("  Mock baseline = New optimized / (1 - improvement% / 100)")
    print("  This assumes the same improvement rate as the previous comparison")
    
    print("\n" + "=" * 100)

if __name__ == "__main__":
    main() 
