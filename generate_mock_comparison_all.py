#!/usr/bin/env python3
"""
Generate complete comparison table with mock baseline data for n=3, n=5, and n=7
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
    # Previous improvement percentages for each n value
    previous_improvements = {
        3: {
            'Non-threshold DKG': -30.8,
            'Threshold DKG': -45.7,
            'Auxiliary data generation': -0.8,
            'Signing protocol': 24.5
        },
        5: {
            'Non-threshold DKG': 2.4,
            'Threshold DKG': 20.1,
            'Auxiliary data generation': -0.4,
            'Signing protocol': 23.0
        },
        7: {
            'Non-threshold DKG': 1.1,
            'Threshold DKG': 1.2,
            'Auxiliary data generation': -1.5,
            'Signing protocol': 26.4
        }
    }
    
    # Extract new optimized data
    new_file = "../fork-cggmp21/logs/measure-perf/250623_13h55_disable_precomputable.txt"
    new_data = extract_performance_data(new_file)
    
    print("=" * 120)
    print("MOCK BASELINE COMPARISON FOR n=3, n=5, n=7 (NEW OPTIMIZED DATA)")
    print("=" * 120)
    print()
    
    # Generate comparison data for all n values
    all_comparison_data = []
    
    for n in [3, 5, 7]:
        if n not in new_data:
            print(f"Warning: No data found for n={n} in the new file")
            continue
        
        print(f"📊 n = {n}")
        print("=" * 80)
        
        n_data = new_data[n]
        n_improvements = previous_improvements[n]
        
        for protocol_name, improvement in n_improvements.items():
            # Try to find matching protocol in new data
            optimized_time = None
            
            if protocol_name in n_data:
                optimized_time = n_data[protocol_name]
            elif protocol_name == 'Signing protocol' and 'Threshold signing protocol' in n_data:
                # Map "Signing protocol" to "Threshold signing protocol"
                optimized_time = n_data['Threshold signing protocol']
            
            if optimized_time is not None:
                mock_baseline = calculate_mock_baseline(optimized_time, improvement)
                
                # Format display values
                if optimized_time < 1000:
                    optimized_display = f"{optimized_time:.2f} ms"
                else:
                    optimized_display = f"{optimized_time:.2f} ms ({optimized_time/1000:.2f}s)"
                
                if mock_baseline < 1000:
                    baseline_display = f"{mock_baseline:.2f} ms"
                else:
                    baseline_display = f"{mock_baseline:.2f} ms ({mock_baseline/1000:.2f}s)"
                
                print(f"  {protocol_name}:")
                print(f"    New optimized: {optimized_display}")
                print(f"    Mock baseline: {baseline_display}")
                print(f"    Expected improvement: {improvement:.1f}%")
                print()
                
                all_comparison_data.append({
                    'n': n,
                    'Protocol': protocol_name,
                    'Mock Baseline (ms)': f"{mock_baseline:.2f}",
                    'New Optimized (ms)': f"{optimized_time:.2f}",
                    'Improvement (%)': f"{improvement:.1f}%"
                })
            else:
                print(f"  {protocol_name}: NOT FOUND in new data")
                print()
        
        print()
    
    # Display comprehensive table
    print("=" * 120)
    print("COMPREHENSIVE SUMMARY TABLE")
    print("=" * 120)
    
    # Group by protocol for better readability
    protocols = ['Non-threshold DKG', 'Threshold DKG', 'Auxiliary data generation', 'Signing protocol']
    
    for protocol in protocols:
        protocol_data = [row for row in all_comparison_data if row['Protocol'] == protocol]
        if protocol_data:
            print(f"\n🔧 {protocol}")
            print("=" * 80)
            print("| n | Mock Baseline (ms) | New Optimized (ms) | Improvement (%) |")
            print("|---|-------------------|-------------------|-----------------|")
            
            for row in protocol_data:
                print(f"| {row['n']} | {row['Mock Baseline (ms)']:>16} | {row['New Optimized (ms)']:>16} | {row['Improvement (%)']:>13} |")
    
    # Save to CSV
    with open('mock_baseline_comparison_n357.csv', 'w', newline='') as csvfile:
        fieldnames = ['n', 'Protocol', 'Mock Baseline (ms)', 'New Optimized (ms)', 'Improvement (%)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in all_comparison_data:
            writer.writerow(row)
    
    print(f"\n\nResults saved to: mock_baseline_comparison_n357.csv")
    
    # Display key insights
    print("\n" + "=" * 120)
    print("KEY INSIGHTS BY PROTOCOL:")
    print("=" * 120)
    
    for protocol in protocols:
        protocol_data = [row for row in all_comparison_data if row['Protocol'] == protocol]
        if protocol_data:
            print(f"\n📈 {protocol}:")
            
            improvements = [float(row['Improvement (%)'].rstrip('%')) for row in protocol_data]
            avg_improvement = sum(improvements) / len(improvements)
            
            print(f"  Average improvement: {avg_improvement:.1f}%")
            
            for row in protocol_data:
                improvement = float(row['Improvement (%)'].rstrip('%'))
                if improvement > 0:
                    status = "✅ Improvement"
                else:
                    status = "❌ Regression"
                
                print(f"  n={row['n']}: {improvement:>5.1f}% {status}")
    
    print("\n🔧 Calculation Method:")
    print("  Mock baseline = New optimized / (1 - improvement% / 100)")
    print("  Based on improvement percentages from previous batch optimization comparison")
    
    print("\n" + "=" * 120)

if __name__ == "__main__":
    main() 
