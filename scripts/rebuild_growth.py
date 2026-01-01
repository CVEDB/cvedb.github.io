#!/usr/bin/env python3
"""
Growth Analysis Rebuild Script
Standalone script to rebuild growth analysis data and regenerate the Growth Intelligence Dashboard
"""

import json
import sys
from pathlib import Path

# Add src to path if not installed
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

try:
    from cvedb.analysis.yearly import YearlyAnalyzer
except ImportError:
    print("❌ Error: Could not import cvedb.analysis.yearly")
    sys.exit(1)

def main():
    """Main function to rebuild growth analysis"""
    print("🚀 Growth Analysis Rebuild")
    print("=" * 40)
    
    # Initialize paths
    cache_dir = PROJECT_ROOT / 'data' / 'raw'
    data_output_dir = PROJECT_ROOT / 'dist' / 'data'
    
    # Ensure output exists
    data_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize analyzer
    print("\n🔧 Initializing Yearly Analyzer...")
    analyzer = YearlyAnalyzer(cache_dir=cache_dir)
    
    # Generate year data first (required for growth analysis)
    print("\n📅 Generating year data...")
    all_year_data = analyzer.generate_year_data_json(data_output_dir)
    
    if not all_year_data:
        print("❌ No year data available for growth analysis")
        return False
        
    print(f"✅ Generated data for {len(all_year_data)} years")
    
    # Generate comprehensive growth analysis
    print("\n📈 Generating comprehensive growth analysis...")
    growth_analysis = analyzer.generate_growth_analysis(all_year_data, data_output_dir)
    
    if growth_analysis:
        print("✅ Comprehensive growth analysis generated successfully")
    else:
        print("❌ Failed to generate comprehensive growth analysis")
        return False
        
    print("\n🎉 Growth analysis rebuild completed successfullly!")
    print(f"📁 Files updated in: {data_output_dir}")
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
