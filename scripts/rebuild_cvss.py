#!/usr/bin/env python3
"""
CVSS Analysis Rebuild Script
Quick rebuild script for CVSS analysis only - much faster than full site rebuild
"""

import sys
import json
from datetime import datetime
from pathlib import Path

# Add src to path if not installed
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

try:
    from cvedb.analysis.cvss import CVSSAnalyzer
except ImportError:
    print("❌ Error: Could not import cvedb.analysis.cvss")
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
    """Rebuild CVSS analysis only"""
    print("📊 CVSS Analysis Quick Rebuild")
    print("=" * 40)
    
    # Set up paths
    cache_dir = PROJECT_ROOT / 'data' / 'raw'
    data_dir = PROJECT_ROOT / 'dist' / 'data'
    
    # Initialize CVSS analyzer
    cvss_analyzer = CVSSAnalyzer(PROJECT_ROOT, cache_dir, data_dir)
    
    try:
        # Load existing year data
        print("📂 Loading existing year data...")
        all_year_data = load_all_year_data(data_dir)
        print(f"✅ Loaded {len(all_year_data)} year data files")
        
        if not all_year_data:
            print("⚠️ No year data found in dist/data. Use full build first if needed.")
            # We don't exit 1 here, maybe they want to build from scratch
        
        # Generate comprehensive CVSS analysis
        print("\n🔄 Generating comprehensive CVSS analysis...")
        cvss_analyzer.generate_cvss_analysis(all_year_data)
        
        # Generate current year CVSS analysis
        current_year = datetime.now().year
        current_year_data = next((year for year in all_year_data if str(year.get('year')) == str(current_year)), {})
        
        if current_year_data:
            print(f"\n🗓️  Generating {current_year} CVSS analysis...")
            cvss_analyzer.generate_current_year_cvss_analysis(current_year_data)
        
        print("\n" + "=" * 40)
        print("✅ CVSS analysis rebuild completed!")
        print(f"📁 Files updated in: {data_dir}")
        return True
        
    except Exception as e:
        print(f"\n❌ CVSS analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
