#!/usr/bin/env python3
"""
CPE Analysis Rebuild Script
Quick rebuild script for CPE analysis only - much faster than full site rebuild
"""

import sys
import json
from datetime import datetime
from pathlib import Path

# Add src to path if not installed
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

try:
    from cvedb.analysis.cpe import CPEAnalyzer
except ImportError:
    print("❌ Error: Could not import cvedb.analysis.cpe")
    sys.exit(1)

def load_all_year_data(data_dir):
    """Load existing year data files"""
    all_year_data = []
    for year_file in sorted(data_dir.glob('cve_*.json')):
        try:
            with open(year_file, 'r') as f:
                all_year_data.append(json.load(f))
        except Exception:
            continue
    return all_year_data

def main():
    """Main rebuild function"""
    print("🔍 CPE Analysis Quick Rebuild")
    print("=" * 40)
    
    # Setup paths
    cache_dir = PROJECT_ROOT / 'data' / 'raw'
    data_dir = PROJECT_ROOT / 'dist' / 'data'
    
    # Initialize CPE analyzer
    print("📊 Initializing CPE analyzer...")
    cpe_analyzer = CPEAnalyzer(PROJECT_ROOT, cache_dir, data_dir)
    
    # Load existing year data for context (if available)
    print("📂 Loading existing year data...")
    all_year_data = load_all_year_data(data_dir)
    
    # Generate comprehensive CPE analysis
    print("\n🔍 Generating comprehensive CPE analysis...")
    try:
        cpe_analyzer.generate_cpe_analysis(all_year_data)
        print("  ✅ Comprehensive CPE analysis generated")
    except Exception as e:
        print(f"  ❌ Error generating comprehensive CPE analysis: {e}")
        return 1
    
    # Generate current year CPE analysis
    print("\n📅 Generating current year CPE analysis...")
    try:
        current_year = datetime.now().year
        current_year_data = next((data for data in all_year_data if str(data.get('year')) == str(current_year)), {})
        cpe_analyzer.generate_current_year_cpe_analysis(current_year_data)
        print("  ✅ Current year CPE analysis generated")
    except Exception as e:
        print(f"  ❌ Error generating current year CPE analysis: {e}")
    
    print("\n" + "=" * 40)
    print("🎉 CPE Analysis Rebuild Complete!")
    print(f"📁 Files updated in: {data_dir}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
