#!/usr/bin/env python3
"""
Mock baseline generator for CGGMP21 protocol benchmarks
Generates mock baseline data using improvement percentages from previous results
"""

import random
import csv
from typing import Dict

def generate_mock_baseline(optimized_ms: float, improvement_percent: float, epsilon_range: tuple = (1, 5)) -> float:
    """
    Generate mock baseline using the formula: baseline = optimized / (100 - improvement_percent) * 100
    Add random epsilon for variation
    """
    # Add random epsilon to improvement percentage
    epsilon = random.uniform(epsilon_range[0], epsilon_range[1])
    adjusted_improvement = improvement_percent + random.choice([-1, 1]) * epsilon
    
    # Calculate baseline using the formula
    baseline = optimized_ms / (100 - adjusted_improvement) * 100
    return baseline, adjusted_improvement

def main():
    # Set random seed for reproducible results
    random.seed(42)
    
    # New optimized data from 250623_13h55_disable_precomputable.txt (converted to ms)
    new_optimized_data = {
        3: {
            'Threshold signing protocol': 30280.0,  # 30.28s
            'Hierarchical threshold signing protocol': 13490.0   # 13.49s
        },
        5: {
            'Threshold signing protocol': 56290.0,  # 56.29s
            'Hierarchical threshold signing protocol': 33410.0   # 33.41s
        },
        7: {
            'Threshold signing protocol': 90050.0,  # 90.05s
            'Hierarchical threshold signing protocol': 74330.0   # 74.33s
        }
    }
    
    # Previous improvement percentages from user's results
    previous_improvements = {
        'Threshold signing protocol': {3: 61.2, 5: 27.3, 7: 29.3},
        'Hierarchical threshold signing protocol': {3: 24.8, 5: 27.7, 7: 32.6}
    }
    
    print("=" * 100)
    print("MOCK BASELINE DATA GENERATOR")
    print("=" * 100)
    print("Using improvement percentages from previous results with epsilon variation (±1-5%)")
    print("Formula: baseline = optimized / (100 - improvement_percent) * 100")
    print()
    
    results = []
    
    for protocol in ['Threshold signing protocol', 'Hierarchical threshold signing protocol']:
        print(f"\n🔧 {protocol}")
        print("=" * 70)
        
        for n in [3, 5, 7]:
            optimized_ms = new_optimized_data[n][protocol]
            base_improvement = previous_improvements[protocol][n]
            
            # Generate mock baseline with epsilon variation
            mock_baseline, actual_improvement = generate_mock_baseline(optimized_ms, base_improvement)
            
            print(f"  n = {n}:")
            print(f"    New optimized:     {optimized_ms:>10.2f} ms")
            print(f"    Base improvement:  {base_improvement:>10.1f}%")
            print(f"    Applied improvement: {actual_improvement:>8.1f}%")
            print(f"    Mock baseline:     {mock_baseline:>10.2f} ms")
            print(f"    Calculated improvement: {((mock_baseline - optimized_ms) / mock_baseline * 100):>5.1f}%")
            print()
            
            # Store results
            results.append({
                'n': n,
                'Protocol': protocol,
                'Mock Baseline (ms)': f"{mock_baseline:.2f}",
                'New Optimized (ms)': f"{optimized_ms:.2f}",
                'Applied Improvement (%)': f"{actual_improvement:.1f}%"
            })
    
    # Create summary table
    print("\n" + "=" * 100)
    print("GENERATED MOCK BASELINE SUMMARY TABLE")
    print("=" * 100)
    
    # Table headers
    headers = ['n', 'Protocol', 'Mock Baseline (ms)', 'New Optimized (ms)', 'Applied Improvement (%)']
    
    # Calculate column widths
    col_widths = [len(header) for header in headers]
    for row in results:
        col_widths[0] = max(col_widths[0], len(str(row['n'])))
        col_widths[1] = max(col_widths[1], len(row['Protocol']))
        col_widths[2] = max(col_widths[2], len(row['Mock Baseline (ms)']))
        col_widths[3] = max(col_widths[3], len(row['New Optimized (ms)']))
        col_widths[4] = max(col_widths[4], len(row['Applied Improvement (%)']))
    
    # Print header
    header_row = "| " + " | ".join(f"{headers[i]:{col_widths[i]}}" for i in range(len(headers))) + " |"
    print(header_row)
    print("|" + "|".join("-" * (col_widths[i] + 2) for i in range(len(headers))) + "|")
    
    # Print rows
    for row in results:
        data_row = "| " + " | ".join([
            f"{row['n']:{col_widths[0]}}",
            f"{row['Protocol']:{col_widths[1]}}",
            f"{row['Mock Baseline (ms)']:{col_widths[2]}}",
            f"{row['New Optimized (ms)']:{col_widths[3]}}",
            f"{row['Applied Improvement (%)']:{col_widths[4]}}"
        ]) + " |"
        print(data_row)
    
    # Save to CSV
    csv_filename = "mock_baseline_comparison.csv"
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['n', 'Protocol', 'Mock Baseline (ms)', 'New Optimized (ms)', 'Applied Improvement (%)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    
    print(f"\nResults saved to {csv_filename}")
    
    # Summary statistics
    print("\n" + "=" * 100)
    print("SUMMARY STATISTICS")
    print("=" * 100)
    
    for protocol in ['Threshold signing protocol', 'Hierarchical threshold signing protocol']:
        protocol_results = [r for r in results if r['Protocol'] == protocol]
        improvements = [float(r['Applied Improvement (%)'].rstrip('%')) for r in protocol_results]
        avg_improvement = sum(improvements) / len(improvements)
        print(f"{protocol}: {avg_improvement:.1f}% average improvement")
    
    print(f"\nGenerated mock baseline data for n = 3, 5, 7")
    print(f"Applied epsilon variation: ±1-5% to base improvement percentages")

if __name__ == "__main__":
    main() 
