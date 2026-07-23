#!/usr/bin/env python3
"""
Performance analyzer for CGGMP21 protocol benchmarks
Parses log files and extracts key performance metrics
"""

import re
import pandas as pd
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import json

class PerformanceAnalyzer:
    def __init__(self):
        self.time_units = {
            'ns': 1e-9,
            'µs': 1e-6,
            'ms': 1e-3,
            's': 1.0
        }
        
    def parse_time(self, time_str: str) -> float:
        """Convert time string to seconds"""
        time_str = time_str.strip()
        for unit, multiplier in self.time_units.items():
            if time_str.endswith(unit):
                return float(time_str[:-len(unit)]) * multiplier
        return float(time_str)
    
    def parse_log_file(self, file_path: str) -> Dict:
        """Parse a log file and extract performance data"""
        with open(file_path, 'r') as f:
            content = f.read()
            
        results = {}
        
        # Split by n values
        n_sections = re.split(r'\nn = (\d+)', content)
        
        for i in range(1, len(n_sections), 2):
            n = int(n_sections[i])
            section_content = n_sections[i + 1]
            
            results[n] = self._parse_n_section(section_content)
            
        return results
    
    def _parse_n_section(self, content: str) -> Dict:
        """Parse a section for a specific n value"""
        protocols = {}
        
        # Find all protocol sections
        protocol_patterns = [
            (r'Non-threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Non-threshold DKG'),
            (r'Threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Threshold DKG'),
            (r'Hierarchical threshold DKG\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Hierarchical threshold DKG'),
            (r'Auxiliary data generation protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Auxiliary data generation protocol'),
            (r'Signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Signing protocol'),
            (r'Threshold signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Threshold signing protocol'),
            (r'Hierarchical threshold signing protocol\nProtocol Performance:\n  - Protocol took (.*?) to complete',
             'Hierarchical threshold signing protocol')
        ]
        
        for pattern, protocol_name in protocol_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            if matches:
                total_time = self.parse_time(matches[0])
                protocols[protocol_name] = {
                    'total_time': total_time,
                    'total_time_ms': total_time * 1000
                }
        
        return protocols
    
    def analyze_files(self, original_file: str, optimized_file: str) -> Dict:
        """Analyze both original and optimized files"""
        original_data = self.parse_log_file(original_file)
        optimized_data = self.parse_log_file(optimized_file)
        
        return {
            'original': original_data,
            'optimized': optimized_data
        }
    
    def create_summary_table(self, data: Dict) -> pd.DataFrame:
        """Create a summary table comparing original vs optimized performance"""
        rows = []
        
        for n in sorted(data['original'].keys()):
            if n in data['optimized']:
                for protocol in data['original'][n]:
                    if protocol in data['optimized'][n]:
                        original_time = data['original'][n][protocol]['total_time_ms']
                        optimized_time = data['optimized'][n][protocol]['total_time_ms']
                        improvement = ((original_time - optimized_time) / original_time) * 100
                        
                        rows.append({
                            'n': n,
                            'Protocol': protocol,
                            'Original (ms)': f"{original_time:.2f}",
                            'Optimized (ms)': f"{optimized_time:.2f}",
                            'Improvement (%)': f"{improvement:.1f}%"
                        })
        
        return pd.DataFrame(rows)
    
    def print_summary(self, data: Dict):
        """Print a formatted summary of the results"""
        print("=" * 80)
        print("CGGMP21 PROTOCOL PERFORMANCE ANALYSIS")
        print("=" * 80)
        
        # Create summary table
        df = self.create_summary_table(data)
        
        # Group by n and print results
        for n in sorted(data['original'].keys()):
            print(f"\nn = {n}")
            print("-" * 40)
            
            n_data = df[df['n'] == n]
            if not n_data.empty:
                print(n_data[['Protocol', 'Original (ms)', 'Optimized (ms)', 'Improvement (%)']].to_string(index=False))
            else:
                print("No comparable data available")
        
        print("\n" + "=" * 80)
        print("PERFORMANCE IMPROVEMENTS SUMMARY")
        print("=" * 80)
        
        # Calculate average improvements by protocol
        protocol_improvements = {}
        for _, row in df.iterrows():
            protocol = row['Protocol']
            improvement = float(row['Improvement (%)'].rstrip('%'))
            if protocol not in protocol_improvements:
                protocol_improvements[protocol] = []
            protocol_improvements[protocol].append(improvement)
        
        for protocol, improvements in protocol_improvements.items():
            avg_improvement = sum(improvements) / len(improvements)
            print(f"{protocol}: {avg_improvement:.1f}% average improvement")
    
    def save_results(self, data: Dict, output_file: str):
        """Save results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Results saved to {output_file}")

def main():
    analyzer = PerformanceAnalyzer()
    
    # File paths
    original_file = "cggmp21/logs/measure-perf/202507142140_original.txt"
    optimized_file = "fork-cggmp21/logs/measure-perf/202507142140_optimized.txt"
    
    # Check if files exist
    if not Path(original_file).exists():
        print(f"Error: {original_file} not found")
        return
    
    if not Path(optimized_file).exists():
        print(f"Error: {optimized_file} not found")
        return
    
    # Analyze files
    print("Analyzing performance logs...")
    data = analyzer.analyze_files(original_file, optimized_file)
    
    # Print summary
    analyzer.print_summary(data)
    
    # Save results
    analyzer.save_results(data, "performance_results.json")
    
    # Create detailed CSV export
    df = analyzer.create_summary_table(data)
    df.to_csv("performance_comparison.csv", index=False)
    print("Detailed results saved to performance_comparison.csv")

if __name__ == "__main__":
    main() 
